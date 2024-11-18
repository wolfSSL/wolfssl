/*!
    \brief この関数はDTLS v1.2 クライアントメソッドを初期化します。
    \return 作成に成功した場合は、WOLFSSL_METHODポインタを返します。
    \return メモリ割り当てエラーまたはメソッドの作成の失敗の場合はNULLを返します。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    …
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    \endcode
    \sa wolfSSL_Init
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief  この関数は、wolfSSLv23_client_methodと同様にWOLFSSL_METHODを返します（サーバー/クライアント）。
    \return 作成に成功した場合は、WOLFSSL_METHODポインタを返します。
    \return メモリ割り当てエラーまたはメソッドの作成の失敗の場合はNULLを返します。

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfSSLv23_method());
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfSSLv23_method(void);

/*!
    \ingroup Setup
    \brief  wolfSSLv3_server_method()関数は、アプリケーションがサーバーであることを示すために使用され、SSL3.0プロトコルのみをサポートします。
    この関数は、wolfSSL_CTX_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_server_method(void);

/*!
    \ingroup Setup
    \brief  wolfSSLv3_client_method()関数は、アプリケーションがクライアントであり、SSL 3.0プロトコルのみをサポートすることを示すために使用されます。
    この関数は、wolfSSL_CTX_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_client_method(void);

/*!
    \ingroup Setup
    \brief  wolfTLSv1_server_method()関数は、アプリケーションがサーバーであることを示すために使用され、TLS 1.0プロトコルのみをサポートします。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_server_method(void);

/*!
    \ingroup Setup
    \brief  wolftlsv1_client_method()関数は、アプリケーションがクライアントであり、TLS 1.0プロトコルのみをサポートすることを示すために使用されます。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_client_method(void);

/*!
    \ingroup Setup
    \brief  wolfTLSv1_1_server_method()関数は、アプリケーションがサーバーであることを示すために使用され、TLS 1.1プロトコルのみをサポートします。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_server_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);

/*!
    \ingroup Setup
    \brief  wolfTLSv1_1_client_method()関数は、アプリケーションがクライアントであり、TLS 1.0プロトコルのみをサポートすることを示すために使用されます。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_client_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);

/*!
    \ingroup Setup
    \brief  wolfTLSv1_2_server_method()関数は、アプリケーションがサーバーであることを示すために使用され、TLS 1.2プロトコルのみをサポートします。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);

/*!
    \ingroup Setup
    \brief  wolfTLSv1_2_client_method()関数は、アプリケーションがクライアントであり、TLS 1.2プロトコルのみをサポートすることを示すために使用されます。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWolfssl_method構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);

/*!
    \ingroup Setup
    \brief  wolfdtlsv1_client_method()関数は、アプリケーションがクライアントであり、DTLS 1.0プロトコルのみをサポートすることを示すために使用されます。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    この関数は、WolfSSLがDTLSサポート（--enable-dtls、またはWOLFSSL_DTLSを定義することによって）ビルドされている場合にのみ使用できます。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_client_method(void);

/*!
    \ingroup Setup
    \brief  wolfDTLSv1_server_method()関数は、アプリケーションがサーバーであることを示すために使用され、DTLS 1.0プロトコルのみをサポートします。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    この関数は、WolfSSLがDTLSサポート（--enable-dtls、またはWOLFSSL_DTLSマクロを定義することによって）ビルドされている場合にのみ使用できます。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_server_method(void);

/*!
    \brief  wolfDTLSv1_2_server_method()関数はサーバ側用にWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    \endcode
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);

/*!
    \ingroup Setup

    \brief wolfDTLSv1_3_server_method()関数はアプリケーションがサーバーであることを示すために使用され、DTLS 1.3プロトコルのみをサポートします。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    この関数は、WolfSSLがDTLSサポート（--enable-dtls13、またはWOLFSSL_DTLS13を定義することによって）ビルドされている場合にのみ使用できます。

    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。
    \param なし

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_client_method
*/

WOLFSSL_METHOD *wolfDTLSv1_3_server_method(void);

/*!
    \ingroup Setup

    \brief wolfDTLSv1_3_client_method()関数はアプリケーションがクライアントであることを示すために使用され、DTLS 1.3プロトコルのみをサポートします。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    この関数は、WolfSSLがDTLSサポート（--enable-dtls13、またはWOLFSSL_DTLS13を定義することによって）ビルドされている場合にのみ使用できます。

    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。
    \param なし


    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_server_method
*/
WOLFSSL_METHOD* wolfDTLSv1_3_client_method(void);

/*!
    \ingroup Setup

    \brief wolfDTLS_server_method()関数はアプリケーションがサーバーであることを示すために使用され、
    可能な限り高いバージョン最小バージョンのDTLSプロトコルをサポートします。
    デフォルトの最小バージョンはWOLFSSL_MIN_DTLS_DOWNGRADEマクロでの指定をもとにしていて、
    実行時にwolfSSL_SetMinVersion()で変更することができます。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    この関数は、WolfSSLがDTLSサポート（--enable-dtls、またはWOLFSSL_DTLSを定義することによって）ビルドされている場合にのみ使用できます。


    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。
    \param なし

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLS_client_method
    \sa wolfSSL_SetMinVersion
*/
WOLFSSL_METHOD *wolfDTLS_server_method(void);

/*!
    \ingroup Setup

    \brief wolfDTLS_client_method()関数は アプリケーションがクライアントであることを示すために使用され、
    可能な限り高いバージョン最小バージョンのDTLSプロトコルをサポートします。
    デフォルトの最小バージョンはWOLFSSL_MIN_DTLS_DOWNGRADEマクロでの指定をもとにしていて、
    実行時にwolfSSL_SetMinVersion()で変更することができます。
    この関数は、wolfSSL_ctx_new()を使用してSSL/TLSコンテキストを作成するときに使用される新しいWOLFSSL_METHOD構造体のメモリを割り当てて初期化します。
    この関数は、wolfSSLがDTLSサポート（--enable-dtls、またはWOLFSSL_DTLSを定義することによって）ビルドされている場合にのみ使用できます。


    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return XMALLOCを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。
    \param なし


    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLS_server_method
    \sa wolfSSL_SetMinVersion
*/
WOLFSSL_METHOD *wolfDTLS_client_method(void);

/*!
    \brief この関数はサーバー側用にWOLFSSL_METHOD構造体を生成して初期化します。

    \return 成功した場合、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。

    \param なし

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);


/*!
    \ingroup Setup
    \brief  Chacha-Poly Aead Constructionの最初のリリースと新しいバージョンの間にいくつかの違いがあるため、
    古いバージョンを使用してサーバー/クライアントと通信するオプションを追加しました。
    デフォルトでは、wolfSSLは新しいバージョンを使用します。
    \return 0  成功の場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成したWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_use_old_poly(ssl, 1);
    if (ret != 0) {
        // failed to set poly1305 AEAD version
    }
    \endcode
    \sa none
*/
int wolfSSL_use_old_poly(WOLFSSL* ssl, int value);

/*!
    \brief  wolfSSL_dtls_import()関数はシリアライズされたセッション状態を解析するために使われます。
    これにより、ハンドシェイクが完了した後に接続をピックアップすることができます。
    \return  成功した場合、読み取ったバッファの量が返されます。
    \return  すべての失敗した戻り値は0未満になります。
    \return VERSION_ERROR  バージョンの不一致が見つかった場合、(すなわち、DTLS v1とCTXがDTLS v1.2に設定された場合)、Version_Errorが返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf  インポートするシリアル化されたセッション情報を格納するバッファへのポインタ。
    \param sz バッファのサイズ

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    //get information sent from wc_dtls_export function and place it in buf
    fread(buf, 1, bufSz, input);
    ret = wolfSSL_dtls_import(ssl, buf, bufSz);
    if (ret < 0) {
    // handle error case
    }
    // no wolfSSL_accept needed since handshake was already done
    ...
    ret = wolfSSL_write(ssl) and wolfSSL_read(ssl);
    ...
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
int wolfSSL_dtls_import(WOLFSSL* ssl, unsigned char* buf,
                                                               unsigned int sz);


/*!
    \brief  シリアライズされたTLSセッションをインポートします。
    警告：bufには、状態に関する機密情報が含まれており、保存されている場合は保存する前に暗号化されるのが最善です。
    追加のデバッグ情報をマクロWOLFSSL_SESSION_EXPORT_DEBUGを定義して表示できます。
    \return バッファ'buf'から読み込まれたバイト数を返します。
    \param ssl  セッションをインポートするためのWOLFSSL構造体へのポインタ
    \param buf  シリアル化されたセッションを含むバッファへのポインタ
    \param sz  バッファのサイズ

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_export
 */
int wolfSSL_tls_import(WOLFSSL* ssl, const unsigned char* buf,
        unsigned int sz);

/*!
    \brief  wolfSSL_CTX_dtls_set_export()関数はセッションをエクスポートするためのコールバック関数を設定します。
    以前に格納されているエクスポート機能をクリアするためにパラメータfuncにNULLを渡すことが許されます。
    サーバー側で使用され、ハンドシェイクが完了した直後に設定したコールバック関数が呼び出されます。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  NULLまたは予想されない引数が渡された場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param func セッションをエクスポートする際に呼び出す関数ポインタ

    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passes
    // buf (serialized session) to destination
    WOLFSSL_CTX* ctx;
    int ret;
    ...
    ret = wolfSSL_CTX_dtls_set_export(ctx, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_dtls_set_export
    \sa Static buffer use
*/
int wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx, wc_dtls_export func);

/*!
    \brief  wolfSSL_dtls_set_export()関数はセッションをエクスポートする際に呼び出すコールバック関数を登録します。
    以前に登録されているエクスポート関数をクリアするために使うこともできます。
    サーバー側で使用され、ハンドシェイクが完了した直後に設定したコールバック関数が呼び出されます。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  NULLまたは予想されない引数が渡された場合に返されます。
    \param ssl  wolfssl_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param func セッションをエクスポートする際に呼び出す関数ポインタ

    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passes
    // buf (serialized session) to destination
    WOLFSSL* ssl;
    int ret;
    ...
    ret = wolfSSL_dtls_set_export(ssl, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
int wolfSSL_dtls_set_export(WOLFSSL* ssl, wc_dtls_export func);

/*!
    \brief  wolfSSL_dtls_export()関数は提供されたバッファへセッションをシリアル化します。
    セッションをエクスポートするための関数コールバックを使用するよりもメモリオーバーヘッドを減らすことができます。
    関数に渡された引数bufがNULLの場合、szにはWolfSSLセッションのシリアライズに必要なバッファのサイズが設定されます。
    \return 成功した場合、使用されるバッファサイズが返されます。
    \return すべての失敗した戻り値は0未満になります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf  シリアライズしたセッションを保持するためのバッファ。
    \param sz バッファのサイズ

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    ret = wolfSSL_dtls_export(ssl, buf, bufSz);
    if (ret < 0) {
        // handle error case
    }
    ...
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
    \sa wolfSSL_dtls_import
*/
int wolfSSL_dtls_export(WOLFSSL* ssl, unsigned char* buf,
                                                              unsigned int* sz);

/*!
    \brief  シリアライズされたTLSセッションをエクスポートします。
    ほとんどの場合、wolfSSL_tls_exportの代わりにwolfssl_get1_sessionを使用する必要があります。
    追加のデバッグ情報をマクロWOLFSSL_SESSION_EXPORT_DEBUGを定義して表示できます。
    警告：bufには、状態に関する機密情報が含まれており、保存する場合は保存する前に暗号化されるのが最善です。
    \return バッファ'buf'に書き込まれたバイト数
    \param ssl  セッションをエクスポートするためのWOLFSSL構造体へのポインタ
    \param buf シリアライズされたセッションの出力先バッファへのポインタ
    \param sz 出力先バッファのサイズ

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_import
 */
int wolfSSL_tls_export(WOLFSSL* ssl, unsigned char* buf,
        unsigned int* sz);

/*!
    \brief  この関数はCTX用に静的メモリ領域を設定する目的に使用されます。
    設定された静的メモリ領域はCTXの有効期間およびCTXから作成された全てのSSLオブジェクトに使用されます。
    引数ctxにNULLを渡し、wolfSSL_method_func関数を渡すことによって、CTX自体の作成も静的メモリを使用します。
    wolfssl_method_funcは次のシグネチャとなっています:wolfssl_method *（* wolfssl_method_func)(void *heap)。
    引数maxに0を渡すと、設定されていないものとして動作し、最大の同時使用制限が適用されません。
    引数flagに渡した値によって、メモリの使用方法と動作が決まります。
    利用可能なフラグ値は次のとおりです：
    0 - デフォルトの一般メモリ、
    WOLFMEM_IO_POOL - メッセージの受送信の際の入出力バッファとして使用され渡されたバッファ内のすべてのメモリがIOに使用されます、
    WOLFMEM_IO_FIXED  -  WOLFMEM_IO_POOLと同じですが、各SSLは2つのバッファを自分のライフタイムの間保持して使用します。
    WOLFMEM_TRACK_STATS  - 各SSLは実行中にメモリ使用統計を追跡します。

    \return SSL_SUCCESS  成功した場合に返されます。に返されます。
    \return SSL_FAILURE  失敗した場合に返されます。

    \param ctx  WOLFSSL_CTX構造体へのポインタのポインタ
    \param method  メソッド関数（例えば、wolfSSLv23_server_method_ex）でctxがNULLでない場合はNULLにする必要があります。
    \param buf  すべての操作に使用するメモリバッファへのポインタ。
    \param sz  渡されているメモリバッファのサイズ。
    \param flag  メモリの使用タイプ
    \param max 同時使用の最大値

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    unsigned char IO[MAX];
    int IOSz = MAX;
    int flag = WOLFMEM_IO_FIXED | WOLFMEM_TRACK_STATS;
    ...
    // create ctx also using static memory, start with general memory to use
    ctx = NULL:
    ret = wolfSSL_CTX_load_static_memory(&ctx, wolfSSLv23_server_method_ex,
    memory, memorySz, 0,    MAX_CONCURRENT_HANDSHAKES);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    // load in memory for use with IO
    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL, IO, IOSz, flag,
    MAX_CONCURRENT_IO);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    ...
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_is_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx,
                                            wolfSSL_method_func method,
                                            unsigned char* buf, unsigned int sz,
                                            int flag, int max);

/*!
    \brief  この関数は現時点の接続に関する振る舞いの変更は行いません。
    静的メモリ使用量に関する情報を収集するためにのみ使用されます。
    \return 1  CTXの静的メモリを使用している場合に返されます。
    \return 0  静的メモリを使用していない場合に返されます。

    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param mem_stats 静的メモリの使用量に関する情報を保持するWOLFSSL_MEM_STATS構造体へのポインタ


    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int ret;
    WOLFSSL_MEM_STATS mem_stats;
    ...
    //get information about static memory with CTX
    ret = wolfSSL_CTX_is_static_memory(ctx, &mem_stats);
    if (ret == 1) {
        // handle case of is using static memory
        // print out or inspect elements of mem_stats
    }
    if (ret == 0) {
        //handle case of ctx not using static memory
    }
    …
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_load_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx,
                                                 WOLFSSL_MEM_STATS* mem_stats);

/*!
    \brief  wolfSSL_is_static_memory関数はSSLの静的メモリ使用量に関する情報を集めます。
    戻り値は、静的メモリが使用されているかどうかを示します。
    引数sslの上位のWOLFSSL_CTXに静的メモリを使用するように指定してあり、WOLFMEM_TRACK_STATSが定義されている場合に
    引数mem_statsに情報がセットされます。
    \return 1  静的メモリを使用している場合に返されます。
    \return 0  静的メモリを使用していない場合に返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param mem_stats 静的メモリの使用量に関する情報を保持するWOLFSSL_MEM_STATS構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    WOLFSSL_MEM_CONN_STATS mem_stats;
    ...
    ret = wolfSSL_is_static_memory(ssl, mem_stats);
    if (ret == 1) {
        // handle case when is static memory
        // investigate elements in mem_stats if WOLFMEM_TRACK_STATS flag
    }
    ...
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_is_static_memory
*/
int wolfSSL_is_static_memory(WOLFSSL* ssl,
                                            WOLFSSL_MEM_CONN_STATS* mem_stats);

/*!
    \ingroup CertsKeys
    \brief  この関数は証明書ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。
    ファイルは引数fileによって提供されます。
    引数formatは、ファイルのフォーマットタイプ（SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM）を指定します。
    適切な使用法の例をご覧ください。

    \return SSL_SUCCESS  成功した場合に返されます。に返されます。
    \return SSL_FAILURE  失敗時に返されます。失敗した場合の可能な原因としては、
    ファイルが誤った形式の場合、または引数formatを使用して誤ったフォーマットが指定されている、
    あるいはファイルが存在しない、あるいは読み取ることができない、または破損している、
    メモリ不足が発生、Base16のデコードに失敗しているなどの原因が考えられます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ
    \param file ロードする証明書を含むファイルパス文字列。
    \param format ロードする証明書のフォーマット：SSL_FILETYPE_ASN1 あるいは SSL_FILETYPE_PEM

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_file(ctx, “./client-cert.pem”,
                                     SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX* ctx, const char* file,
                                     int format);

/*!
    \ingroup CertsKeys

    \brief  この関数は、秘密鍵ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。
    ファイルは引数fileによって提供されます。
    引数formatは、次のファイルのフォーマットタイプを指定します：SSL_FILETYPE_ASN1　あるいは SSL_FILETYPE_PEM。
    適切な使用法の例をご覧ください。
    外部キーストアを使用し、秘密鍵を持っていない場合は、
    代わりに公開鍵を入力してcryptoコールバックを登録して署名を処理することができます。
    このためには、cryptoコールバックまたはPKコールバックを使用したコンフィギュレーションでビルドします。
    cryptoコールバックを有効にするには、--enable-cryptocbまたはWOLF_CRYPTO_CBマクロを使用し、
    wc_CryptoCb_RegisterDeviceを使用して暗号コールバックを登録し、
    wolfSSL_CTX_SetDevIdを使用して関連するdevidを設定します。

    \return SSL_SUCCESS  成功した場合に返されます。に返されます。
    \return SSL_FAILURE  関数呼び出しが失敗した場合の可能な原因としては、
    ファイルが誤った形式の場合、または引数formatを使用して誤ったフォーマットが指定されている、
    あるいはファイルが存在しない、あるいは読み取ることができない、または破損している、
    メモリ不足が発生、Base16のデコードに失敗しているなどの原因が考えられます
    \param なし

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, “./server-key.pem”,
                                    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wc_CryptoCb_RegisterDevice
    \sa wolfSSL_CTX_SetDevId
*/
int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX* ctx, const char* file, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、PEM形式のCA証明書ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。
    これらの証明書は、信頼できるルート証明書として扱われ、SSLハンドシェイク中にピアから受信した証明書を検証するために使用されます。
    引数fileによって提供されるルート証明書ファイルは、単一の証明書または複数の証明書を含むファイルでの場合があります。
    複数のCA証明書が同じファイルに含まれている場合、wolfSSLはファイルに表示されているのと同じ順序でそれらをロードします。
    引数pathは、信頼できるルートCAの証明書を含むディレクトリの名前へのポインタです。
    引数fileがNULLではない場合、パスが必要でない場合はNULLとして指定できます。
    引数pathが指定されていてかつNO_WOLFSSL_DIRが定義されていない場合には、
    wolfSSLライブラリは指定されたディレクトリに存在するすべてのCA証明書をロードします。
    この関数はディレクトリ内のすべてのファイルをロードしようとします。
    この関数は、ヘッダーに "-----BEGIN CERTIFICATE-----"を持つPEMフォーマットされたCERT_TYPEファイルを期待しています。

    \return SSL_SUCCESS  成功した場合に返されます。に返されます。
    \return SSL_FAILURE  CTXがNULLの場合、またはファイルとパスの両方がNULLの場合に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合、読み込めない場合、または破損している場合に返されます。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return ASN_BEFORE_DATE_E  現在の日付が使用開始日より前の場合に返されます。
    \return ASN_AFTER_DATE_E  現在の日付が使用期限後より後の場合に返されます。
    \return BUFFER_E  チェーンバッファが受信バッファよりも大きい場合に返されます。
    \return BAD_PATH_ERROR  opendir()がパスを開こうとして失敗した場合に返されます。

    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param file PEM形式のCA証明書を含むファイルの名前へのポインタ。
    \param path CA証明書を含んでいるディレクトリのディレクトリの名前へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations(ctx, “./ca-cert.pem”, NULL);
    if (ret != WOLFSSL_SUCCESS) {
    	// error loading CA certs
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_locations_ex
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX* ctx, const char* file,
                                                const char* path);

/*!
    \brief  この関数は、PEM形式のCA証明書ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。
    これらの証明書は、信頼できるルート証明書として扱われ、SSLハンドシェイク中にピアから受信した証明書を検証するために使用されます。
    引数fileによって提供されるルート証明書ファイルは、単一の証明書または複数の証明書を含むファイルでの場合があります。
    複数のCA証明書が同じファイルに含まれている場合、wolfSSLはファイルに表示されているのと同じ順序でそれらをロードします。
    引数pathは、信頼できるルートCAの証明書を含むディレクトリの名前へのポインタです。
    引数fileがNULLではない場合、パスが必要でない場合はNULLとして指定できます。
    引数pathが指定されていてかつNO_WOLFSSL_DIRが定義されていない場合には、
    wolfSSLライブラリは指定されたディレクトリに存在するすべてのCA証明書をロードします。
    この関数は引数flagsに基づいてディレクトリ内のすべてのファイルをロードしようとします。
    この関数は、ヘッダーに "-----BEGIN CERTIFICATE-----"を持つPEMフォーマットされたCERT_TYPEファイルを期待しています。

    \return SSL_SUCCESS  成功した場合に返されます。に返されます。
    \return SSL_FAILURE  CTXがNULLの場合、またはファイルとパスの両方がNULLの場合に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合、読み込めない場合、または破損している場合に返されます。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return ASN_BEFORE_DATE_E  現在の日付が使用開始日より前の場合に返されます。
    \return ASN_AFTER_DATE_E  現在の日付が使用期限後より後の場合に返されます。
    \return BUFFER_E  チェーンバッファが受信バッファよりも大きい場合に返されます。
    \return BAD_PATH_ERROR  opendir()がパスを開こうとして失敗した場合に返されます。

    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param file PEM形式のCA証明書を含むファイルの名前へのポインタ。
    \param path CA証明書を含んでいるディレクトリのフォルダーパス
    \param flags 指定可能なマスク値: WOLFSSL_LOAD_FLAG_IGNORE_ERR,
    WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY, WOLFSSL_LOAD_FLAG_PEM_CA_ONLY

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations_ex(ctx, NULL, “./certs/external",
        WOLFSSL_LOAD_FLAG_PEM_CA_ONLY);
    if (ret != WOLFSSL_SUCCESS) {
        // error loading CA certs
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_load_verify_locations_ex(WOLFSSL_CTX* ctx, const char* file,
                                         const char* path, unsigned int flags);

/*!
    \ingroup CertsKeys

    \brief この関数は、wolfSSL_CTX_load_system_CA_certs が呼び出されたときに、
    wolfSSLがシステムCA証明書を検索するディレクトリを表す文字列の配列へのポインタを返します。

    \return 成功時には文字列配列へのポインタを返します。
    \return NULL 失敗時に返します。

    \param num word32型変数へのポインタ。文字列配列の長さを格納します。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    const char** dirs;
    word32 numDirs;

    dirs = wolfSSL_get_system_CA_dirs(&numDirs);
    for (int i = 0; i < numDirs; ++i) {
        printf("Potential system CA dir: %s\n", dirs[i]);
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_system_CA_certs
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_locations_ex
*/
const char** wolfSSL_get_system_CA_dirs(word32* num);

/*!
    \ingroup CertsKeys

    \brief この関数は、CA証明書をOS依存のCA証明書ストアからWOLFSSL_CTXにロードしようとします。
    ロードされた証明書は信頼されます。
    サポートおよびテストされているプラットフォームは、Linux(Debian、Ubuntu、Gentoo、Fedora、RHEL)、
    Windows 10/11、Android、Apple OS X、iOSです。

    \return WOLFSSL_SUCCESS 成功時に返されます。
    \return WOLFSSL_BAD_PATH システムCA証明書がロードできなかった場合に返されます。
    \return WOLFSSL_FAILURE そのほかのエラー発生時（Windows証明書ストアが正常にクローズされない等）

    \param ctx wolfSSL_CTX_new()で生成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_system_CA_certs(ctx,);
    if (ret != WOLFSSL_SUCCESS) {
        // error loading system CA certs
    }
    ...
    \endcode

    \sa wolfSSL_get_system_CA_dirs
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_locations_ex
*/
int wolfSSL_CTX_load_system_CA_certs(WOLFSSL_CTX* ctx);


/*!
    \ingroup Setup
    \brief  この関数は、TLS/SSLハンドシェイクを実行するときにピアを検証するために使用する証明書をロードします。
    ハンドシェイク中に送信されたピア証明書は、この関数で指定された証明書のSKIDと署名を比較することによって検証されます。
    これら2つのことが一致しない場合は、ピア証明書の検証にはロードされたCA証明書が使用されます。
    この機能はWOLFSSL_TRUST_PEER_CERTマクロを定義することで機能を有効にできます。
    適切な使用法は例をご覧ください。

    \return SSL_SUCCES  成功時に返されます。
    \return SSL_FAILURE  CTXがNULLの場合、または両方のファイルと種類が無効な場合に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \param ctx  wolfSSL_CTX_new()で生成されたWOLFSSL_CTX構造体へのポインタ。
    \param file  証明書を含むファイルの名前へのポインタ

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    ...

    ret = wolfSSL_CTX_trust_peer_cert(ctx, “./peer-cert.pem”,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        // error loading trusted peer cert
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_trust_peer_cert(WOLFSSL_CTX* ctx, const char* file, int type);

/*!
    \ingroup CertsKeys
    \brief  この関数は、証明書チェーンをSSLコンテキスト(WOLFSSL_CTX)にロードします。
    証明書チェーンを含むファイルは引数fileによって提供され、PEM形式の証明書を含める必要があります。
    この関数は、最大MAX_CHAIN_DEPTH（既定で9、internal.hで定義されている）数の証明書を処理します。
    この数にはサブジェクト証明書を含みます。

    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  関数呼び出しが失敗した場合、可能な原因としては：誤った形式である場合、
    または「format」引数を使用して誤ったフォーマットが指定されている場合、
    ファイルが存在しない、読み取れない、または破損している、メモリ枯渇などが考えられます。
    \param ctx  wolfSSL_CTX_new()で生成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *ctx,
                                                     const char *file);

/*!
    \ingroup openSSL
    \brief  この関数は、SSL接続で使用されているRSA秘密鍵をSSLコンテキスト(WOLFSSL_CTX)にロードします。
    この関数は、wolfSSLがOpenSSL互換APIが有効（--enable-openSSLExtra、#define OPENSSL_EXTRA）でコンパイルされている場合にのみ利用可能で、
    より一般的に使用されているwolfSSL_CTX_use_PrivateKey_file()関数と同じです。
    ファイル引数には、RSA秘密鍵ファイルへのポインタが、引数formatで指定された形式で含まれています。

    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  関数呼び出しが失敗した場合に返されます。
    失敗の原因には次が考えられます：入力鍵ファイルが誤った形式である、
    または引数formatを使用して誤った形式が与えられている場合、
    ファイルが存在しない、読み込めない、または破損してる、メモリ不足状態が発生。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ
    \param file  フォーマットで指定された形式で、WolfSSL SSLコンテキストにロードされるRSA秘密鍵を含むファイルの名前へのポインタ。
    \param format RSA秘密鍵のエンコード形式を指定します。指定可能なフォーマット値は：SSL_FILETYPE_PEM と SSL_FILETYPE_ASN1

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_RSAPrivateKey_file(ctx, “./server-key.pem”,
                                       SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_RSAPrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX* ctx, const char* file, int format);

/*!
    \ingroup IO
    \brief  この関数は、有効なセッション（NULL以外の引数ssl）が指定された場合に、デフォルトで9の最大チェーン深度を返します。
    \return MAX_CHAIN_DEPTH  WOLFSSL構造体がNULLではない場合に返されます。デフォルトでは値は9です。
    \return BAD_FUNC_ARG  WOLFSSL構造体がNULLの場合に返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    long sslDep = wolfSSL_get_verify_depth(ssl);

    if(sslDep > EXPECTED){
    	// The verified depth is greater than what was expected
    } else {
    	// The verified depth is smaller or equal to the expected value
    }
    \endcode
    \sa wolfSSL_CTX_get_verify_depth
*/
long wolfSSL_get_verify_depth(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSL_CTX構造体構造を使用して証明書チェーン深度を取得します。
    \return MAX_CHAIN_DEPTH  WOLFSSL_CTX構造体がNULLではない場合に返されます。最大証明書チェーンピア深度の定数表現。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がNULLの場合に返されます。

    _Example_
    \code
    WOLFSSL_METHOD method; // protocol method
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    long ret = wolfSSL_CTX_get_verify_depth(ctx);

    if(ret == EXPECTED){
    	//  You have the expected value
    } else {
    	//  Handle an unexpected depth
    }
    \endcode
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_get_verify_depth
*/
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL
    \brief  この関数は証明書ファイルをSSLセッション（WOLFSSL構造体）にロードします。
    証明書ファイルはファイル引数によって提供されます。
    引数formatは、ファイルのフォーマットタイプ（SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM）を指定します。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  関数呼び出しが失敗した場合に返されます。
    可能な原因には次のようなものがあります。
    ファイルが誤った形式、または引数formatを使用して誤った形式が与えられた、
    メモリ不足状態が発生した、ファイルでBase16のデコードが失敗した
    \param ssl  wolfSSL_new()で作成されたWOLFSSL構造体へのポインタ。
    \param file  WOLFSSL構造体にロードされる証明書を含むファイルの名前へのポインタ
    \param format 証明書ファイルのエンコード形式を指定します。指定可能なフォーマット値は：SSL_FILETYPE_PEM と SSL_FILETYPE_ASN1

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_certificate_file(ssl, “./client-cert.pem”,
                                 SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup openSSL
    \brief  この関数は、秘密鍵ファイルをSSLセッション（WOLFSSL構造体）にロードします。
    鍵ファイルは引数fileによって提供されます。
    引数formatは、ファイルのタイプ（SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMが指定可）を指定します。
    外部キーストアを使用し、秘密鍵を持っていない場合は、代わりに公開鍵を入力してCryProコールバックを登録して署名を処理することができます。
    このためには、CryptoコールバックまたはPKコールバックを使用したコンフィグレーションでビルドします。
    Cryptoコールバックを有効にするには、--enable-cryptocbまたはWOLF_CRYPTO_CBマクロを使用してビルドし、
    wc_CryptoCb_RegisterDeviceを使用して暗号コールバックを登録し、
    wolfSSL_SetDevIdを使用して関連するdevIdを設定します。

    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  関数呼び出しが失敗した場合に返されます。
    可能な原因には次のようなものがあります。
    ファイルが誤った形式、または引数formatを使用して誤った形式が与えられた、
    メモリ不足状態が発生した、ファイルでBase16のデコードが失敗した
    \param ssl  wolfSSL_new()で作成されたWOLFSSL構造体へのポインタ。
    \param file  WOLFSSL構造体にロードされる証明書を含むファイルの名前へのポインタ
    \param format 秘密鍵ファイルのエンコード形式を指定します。指定可能なフォーマット値は：SSL_FILETYPE_PEM と SSL_FILETYPE_ASN1

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_PrivateKey_file(ssl, “./server-key.pem”,
                                SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wc_CryptoCb_RegisterDevice
    \sa wolfSSL_SetDevId
*/
int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup openSSL
    \brief  この関数は、証明書チェーンをSSLセッションWOLFSSL構造体）にロードします。
    証明書チェーンを含むファイルは引数fileによって提供され、PEM形式の証明書を含める必要があります。
    この関数は、MAX_CHAIN_DEPTH（既定で9、internal.hで定義されている）証明書に加えて、サブジェクト証明書を処理します。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  関数呼び出しが失敗した場合に返されます。
    可能な原因には次のようなものがあります：
    ファイルが誤った形式、または引数formatを使用して誤った形式が与えられた、
    メモリ不足状態が発生した、ファイルでbase16のデコードが失敗した
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param file  WOLFSSL構造体にロードされる証明書を含むファイルの名前へのポインタ。
    証明書はPEM形式でなければなりません。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ctx;
    ...
    ret = wolfSSL_use_certificate_chain_file(ssl, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_certificate_chain_file(WOLFSSL* ssl, const char *file);

/*!
    \ingroup openSSL
    \brief  この関数は、SSL接続で使用されているRSA秘密鍵をSSLセッション（WOLFSSL構造体）にロードします。
    この関数は、wolfSSLがOpenSSL互換APIを有効（--enable-openSSlExtra、#define OPENSSL_EXTRA）でビルドされている場合にのみ利用可能で、
    より一般的に使用されるwolfSSL_use_PrivateKey_file()関数と同じです。
    引数fileには、RSA秘密鍵ファイルへのポインタが、フォーマットで指定された形式で含まれています。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  関数呼び出しが失敗した場合に返されます。
    可能な原因には次のようなものがあります：
    ファイルが誤った形式、または引数formatを使用して誤った形式が与えられた、
    メモリ不足状態が発生した、ファイルでBase16のデコードが失敗した
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_RSAPrivateKey_file(ssl, “./server-key.pem”,
                                   SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode
    \sa wolfSSL_CTX_use_RSAPrivateKey_file
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
int wolfSSL_use_RSAPrivateKey_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数はwolfSSL_CTX_load_verify_locationsと似ていますが、
    DERフォーマットされたCAファイルをSSLコンテキスト（WOLFSSL_CTX）にロードすることを許可します。
    それはまだPEM形式のCAファイルをロードするためにも使用されるかもしれません。
    これらの証明書は、信頼できるルート証明書として扱われ、SSLハンドシェイク中にピアから受信した証明書を検証するために使用されます。
    ファイル引数によって提供されるルート証明書ファイルは、単一の証明書または複数の証明書を含むファイルでも可能。
    複数のCA証明書が同じファイルに含まれている場合、wolfSSLはファイルに表示されているのと同じ順序でそれらをロードします。
    引数formatは、証明書がSSL_FILETYPE_PEMまたはSSL_FILETYPE_ASN1（DER）のいずれかにある形式を指定します。
    wolfSSL_CTX_load_verify_locationsとは異なり、この関数は特定のディレクトリパスからのCA証明書のロードを許可しません。
    この関数は、wolfSSLライブラリがWOLFSSL_DER_LOADマクロが定義された状態でビルドされたときにのみ利用可能です。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  失敗すると返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ
    \param file  wolfssl SSLコンテキストにロードされるCA証明書を含むファイルの名前をフォーマットで指定された形式で指定します。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_der_load_verify_locations(ctx, “./ca-cert.der”,
                                          SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
	    // error loading CA certs
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_buffer
*/
int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX* ctx,
                                          const char* file, int format);

/*!
    \ingroup Setup
    \brief  この関数は、所望のSSL/TLSプロトコル用メソッド構造体を引数に取って、新しいSSLコンテキストを作成します。
    \return pointer  成功した場合、新しく作成されたWOLFSSL_CTX構造体へのポインタを返します。
    \return NULL  失敗時に返されます。

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    WOLFSSL_METHOD* method = 0;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
    	// context creation failed
    }
    \endcode
    \sa wolfSSL_new
*/
WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);

/*!
    \ingroup Setup
    \brief  この関数はすでに作成されたSSLコンテキスト(WOLFSSL_CTX)を入力として、新しいSSLセッション(WOLFSSL)を作成します。
    \return 成功した場合、新しく作成されたWOLFSSL構造体へのポインタを返します。
    \return NULL  失敗時に返されます。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL*     ssl = NULL;
    WOLFSSL_CTX* ctx = 0;

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
	    // context creation failed
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
	    // SSL object creation failed
    }
    \endcode
    \sa wolfSSL_CTX_new
*/
WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);

/*!
    \ingroup Setup
    \brief  この関数は、SSL接続の入出力機能としてファイル記述子(fd)を割り当てます。通常これはソケットファイル記述子になります。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  失敗時に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param fd SSL/TLS接続に使用するファイルディスクリプタ

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
    	// failed to set SSL file descriptor
    }
    \endcode
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
*/
int  wolfSSL_set_fd (WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup
    \brief この関数はファイルディスクリプタ(fd)をSSLコネクションの入出力手段として設定します。
    通常はソケットファイルディスクリプタが指定されます。この関数はDTLS専用のAPIであり、ソケットは接続済みとマークされます。
    したがって、与えられたfdに対するrecvfromとsendto呼び出しでのaddrとaddr_lenはNULLに設定されます。

    \return SSL_SUCCESS 成功時に返されます。
    \return BAD_FUNC_ARG 失敗時に返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param fd SSL/TLSコネクションに使用するファイルディスクリプタ。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    if (connect(sockfd, peer_addr, peer_addr_len) != 0) {
        // handle connect error
    }
    ...
    ret = wolfSSL_set_dtls_fd_connected(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        // failed to set SSL file descriptor
    }
    \endcode
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
    \sa wolfDTLS_SetChGoodCb
*/
int wolfSSL_set_dtls_fd_connected(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief この関数はDTLS ClientHelloメッセージが正しく処理できた際に呼び出されるコールバック関数を設定します。
            クッキー交換メカニズムを使用する場合(DTLS1.2のHelloVerifyRequest か
            DTLS1.3のクッキー拡張を伴ったHelloRetryRequestのいずれかを使用する場合)には、
            クッキー交換が成功した時点でこのコールバック関数が呼び出されます。
            この機能はひとつのWOLFSSLオブジェクトを新たな接続を待ち受けるリスナーとして使い,
            ClientHelloが検証されたWOLFSSLオブジェクトから絶縁させることができます。
            この場合の検証はクッキー交換かClientHelloが正しいフォーマットになっているかのチェックによってなされます。

           DTLS 1.2:
           https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
           DTLS 1.3:
           https://www.rfc-editor.org/rfc/rfc8446#section-4.2.2

    \return SSL_SUCCESS 成功時に返されます。
    \return BAD_FUNC_ARG 失敗時に返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param fd SSL/TLSコネクションに使用するファイルディスクリプタ。

    _Example_
    \code

    // Called when we have verified a connection
    static int chGoodCb(WOLFSSL* ssl, void* arg)
    {
        // setup peer and file descriptors

    }

    if (wolfDTLS_SetChGoodCb(ssl, chGoodCb, NULL) != WOLFSSL_SUCCESS) {
         // error setting callback
    }
    \endcode

    \sa wolfSSL_set_dtls_fd_connected
*/
int wolfDTLS_SetChGoodCb(WOLFSSL* ssl, ClientHelloGoodCb cb, void* user_ctx);

/*!
    \ingroup IO

    \brief この関数は引数で渡された優先順位の暗号名(Cipher)文字列へのポインタを返します。

    \return 成功時には暗号名(Cipher)文字列へのポインタを返します。
    \return 0 引数で渡された優先順位が範囲外かあるいは無効な値であった場合に返されます。

    \param priority 整数値で指定する優先順位

    _Example_
    \code
    printf("The cipher at 1 is %s", wolfSSL_get_cipher_list(1));
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
char* wolfSSL_get_cipher_list(int priority);

/*!
    \ingroup IO
    \brief  この関数はwolfSSで有効化されている暗号名(Cipher)を取得します。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  引数bufがNULLの場合、または引数lenがゼロ以下の場合に返されます。
    \return BUFFER_E  バッファが十分に大きくなく、オーバーフローする可能性がある場合に返されます。
    \param buf  文字列を格納するバッファへのポインタ。
    \param len バッファのサイズ

    _Example_
    \code
    static void ShowCiphers(void){
	char* ciphers;
	int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

	if(ret == SSL_SUCCES){
	    	printf(“%s\n”, ciphers);
	    }
    }
    \endcode
    \sa GetCipherNames
    \sa wolfSSL_get_cipher_list
    \sa ShowCiphers
*/
int  wolfSSL_get_ciphers(char* buf, int len);

/*!
    \ingroup IO
    \brief  この関数は、引数をwolfSSL_get_cipher_name_internalに渡すことによって、DHE-RSAの形式の暗号名を取得します。
    \return 成功時には一致した暗号スイートの文字列表現を返します。
    \return NULL  エラーまたは暗号が見つからない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    char* cipherS = wolfSSL_get_cipher_name(ssl);

    if(cipher == NULL){
	    // There was not a cipher suite matched
    } else {
	    // There was a cipher suite matched
	    printf(“%s\n”, cipherS);
    }
    \endcode
    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
*/
const char* wolfSSL_get_cipher_name(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は、SSL接続の入出力機能として使用されるファイル記述子(fd)を返します。通常これはソケットファイル記述子になります。
    \return fd  成功時にはSSLセッションに関連つけられているファイル記述子を返します。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_fd(ssl);
    ...
    \endcode
    \sa wolfSSL_set_fd
*/
int  wolfSSL_get_fd(const WOLFSSL*);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSLオブジェクトに基礎となるI/Oがノンブロックであることを通知します。
    アプリケーションがWOLFSSLオブジェクトを作成した後、ブロッキング以外のソケットで使用する場合は、
    wolfssl_set_using_nonblock()を呼び出します。
    これにより、wolfsslオブジェクトは、EWOULDBLOCKを受信することを意味します。

    \return なし
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param nonblock WOLFSSLオブジェクトにノンブロッキングI/Oを使用することを通知するフラグ。
    １を指定することでノンブロッキングI/Oを使用することを指定する。


    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_using_nonblock(ssl, 1);
    \endcode
    \sa wolfSSL_get_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
void wolfSSL_set_using_nonblock(WOLFSSL* ssl, int nonblock);

/*!
    \ingroup IO
    \brief  この機能により、wolfSSLがノンブロッキングI/Oを使用しているかどうかをアプリケーションが判断できます。
    wolfSSLがノンブロッキングI/Oを使用している場合、この関数は1を返します。
    アプリケーションがWOLFSSLオブジェクトを生成した後にwolfSSL_set_using_nonblock()を呼び出してノンブロッキングソケットを使うとこの関数は１を返します。
    これにより、WOLFSSLオブジェクトは、recevfromがタイムアウトせず代わりにEWOULDBLOCKを受信するようになります。

    \return 0  基礎となるI/Oがブロックされています。
    \return 1  基礎となるI/Oは非ブロッキングです。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_get_using_nonblock(ssl);
    if (ret == 1) {
    	// underlying I/O is non-blocking
    }
    ...
    \endcode
    \sa wolfSSL_set_session
*/
int  wolfSSL_get_using_nonblock(WOLFSSL*);

/*!
    \ingroup IO
    \brief  この関数は、バッファあるいはデータから、SSL接続に対して、szバイトを書き込みます。
    必要に応じて、wolfSSL_write()の呼び出し時点ではまだwolfSSL_connect()またはwolfSSL_accept()がまだ呼び出されていない場合、SSL/TLSセッションをネゴシエートします。
    wolfSSL_write()は、ブロックとノンブロッキングI/Oの両方で動作します。
    基礎となる入出力がノンブロッキングに設定されている場合、wolfSSL_write()が要求を満たすことができなかったらwolfSSL_write()は関数呼び出しからすぐに戻ります。
    この場合、wolfSSL_get_error()の呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを返します。
    その結果、基礎となるI/Oが準備ができたら、呼び出し側プロセスはwolfssl_write()への呼び出しを繰り返す必要があります。
    基礎となる入出力がブロックされている場合、WolfSSL_WRITE()は、サイズSZのバッファデータが完全に書かれたかエラーが発生したら、戻るだけです。

    \return 成功時には書き込んだバイト数（1以上）を返します。
    \return 0  失敗したときに返されます。特定のエラーコードについてwolfSSL_get_error()を呼び出します。
    \return SSL_FATAL_ERROR  エラーが発生したとき、または非ブロッキングソケットを使用するときには、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが受信され、再度WOLFSSL_WRITE()を呼び出す必要がある場合は、障害が発生します。特定のエラーコードを取得するには、wolfSSL_get_error()を使用してください。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param data  ピアに送信されるデータを含んでいるバッファへのポインタ。
    \param sz 送信データを含んでいるバッファのサイズ

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags;
    int ret;
    ...

    ret = wolfSSL_write(ssl, msg, msgSz);
    if (ret <= 0) {
    	// wolfSSL_write() failed, call wolfSSL_get_error()
    }
    \endcode
    \sa wolfSSL_send
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_write(WOLFSSL* ssl, const void* data, int sz);

/*!
    \ingroup IO
    \brief  この関数は、SSLセッション(ssl)の内部読み取りバッファからszバイトをバッファデータに読み出します。
    読み取られたバイトは内部受信バッファから削除されます。
    必要に応じて、wolfSSL_read()の呼び出し時点ではまだwolfSSL_connect()またはwolfSSL_accept()がまだ呼び出されていない場合、SSL/TLSセッションをネゴシエートします。
    SSL/TLSプロトコルは、最大サイズのSSLレコードを使用します（最大レコードサイズは<wolfssl_root> /wolfssl/internal.h）。
    そのため、wolfSSLは、レコードを処理および復号することができる前に、SSLレコード全体を内部的に読み取る必要があります。
    このため、wolfSSL_read()への呼び出しは、呼び出し時に復号された最大バッファサイズを返すことができます。
    検索され、次回のwolfSSL_read()への呼び出しで復号される内部wolfSSL受信バッファで待機していない追加の復号データがあるかもしれません。
    szが内部読み取りバッファ内のバイト数より大きい場合、wolfSSL_read()は内部読み取りバッファで使用可能なバイトを返します。
    BYTESが内部読み取りバッファにバッファされていない場合は、wolfSSL_read()への呼び出しは次のレコードの処理をトリガーします。

    \return 成功時には読み取られたバイト数（1以上）を返します。
    \return 0  失敗したときに返されます。これは、クリーン（通知アラートを閉じる）シャットダウンまたはピアが接続を閉じただけであることによって発生する可能性があります。
    特定のエラーコードについてwolfSSL_get_error()を呼び出します。
    \return SSL_FATAL_ERROR  エラーが発生したとき、またはノンブロッキングソケットを使用するときに、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが受信され、再度wolfSSL_read()を呼び出す必要がある場合は、障害が発生します。特定のエラーコードを取得するには、wolfSSL_get_error()を使用してください。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param data  wolfSSL_read()が読み取るデータを格納するバッファへのポインタ。
    \param sz バッファに読み取るデータのサイズ

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }

    See wolfSSL examples (client, server, echoclient, echoserver) for more
    complete examples of wolfSSL_read().
    \endcode
    \sa wolfSSL_recv
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
int  wolfSSL_read(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO
    \brief  この関数はSSLセッション（SSL）内部読み取りバッファからSZバイトをバッファデータにコピーします。この関数は、内部SSLセッション受信バッファ内のデータが削除されていないか変更されていないことを除いて、wolfssl_read()と同じです。必要に応じて、wolfssl_read()のように、wolfssl_peek()はまだwolfssl_connect()またはwolfssl_accept()によってまだ実行されていない場合、wolfssl_peek()はSSL / TLSセッションをネゴシエートします。 SSL/TLSプロトコルは、最大サイズのSSLレコードを使用します（最大レコードサイズは<wolfssl_root> /wolfssl/internal.h）。そのため、WolfSSLは、レコードを処理および復号化することができる前に、SSLレコード全体を内部的に読み取る必要があります。このため、wolfssl_peek()への呼び出しは、呼び出し時に復号化された最大バッファサイズを返すことができます。 wolfssl_peek()/ wolfssl_read()への次の呼び出しで検索および復号化される内部WolfSSL受信バッファ内で待機していない追加の復号化データがあるかもしれません。 SZが内部読み取りバッファ内のバイト数よりも大きい場合、SSL_PEEK()は内部読み取りバッファで使用可能なバイトを返します。バイトが内部読み取りバッファにバッファされていない場合、Wolfssl_peek()への呼び出しは次のレコードの処理をトリガーします。
    \return 成功時には読み取られたバイト数（1以上）を返します。
    \return 0  失敗したときに返されます。これは、クリーン（通知アラートを閉じる）シャットダウンまたはピアが接続を閉じただけであることによって発生する可能性があります。特定のエラーコードについてwolfSSL_get_error()を呼び出します。
    \return SSL_FATAL_ERROR  エラーが発生したとき、またはノンブロッキングソケットを使用するときに、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが受信され、再度wolfSSL_peek()を呼び出す必要がある場合は、障害が発生します。特定のエラーコードを取得するには、wolfSSL_get_error()を使用してください。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param data  wolfSSL_peek()がデータを読み取るバッファー。
    \param sz バッファに読み取るデータのサイズ

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_peek(ssl, reply, sizeof(reply));
    if (input > 0) {
	    // “input” number of bytes returned into buffer “reply”
    }
    \endcode
    \sa wolfSSL_read
*/
int  wolfSSL_peek(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO
    \brief  この関数はサーバー側で呼び出され、SSLクライアントがSSL/TLSハンドシェイクを開始するのを待ちます。
    この関数が呼び出されると、基礎となる通信チャネルはすでに設定されています。
    wolfSSL_accept()は、ブロックとノンブロッキングI/Oの両方で動作します。
    基礎となる入出力がノンブロッキングである場合、wolfSSL_accept()は、基礎となるI/OがwolfSSL_acceptの要求を満たすことができなかったときに戻ります。
    この場合、wolfSSL_get_error()への呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを生成します。
    呼び出しプロセスは、読み取り可能なデータが使用可能であり、wolfSSLが停止した場所を拾うときに、wolfSSL_acceptの呼び出しを繰り返す必要があります。
    ノンブロッキングソケットを使用する場合は、何も実行する必要がありますが、select()を使用して必要な条件を確認できます。
    基礎となるI/Oがブロックされている場合、wolfSSL_accept()はハンドシェイクが終了したら、またはエラーが発生したら戻ります。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FATAL_ERROR  エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
int  wolfSSL_accept(WOLFSSL*);

/*!
    \ingroup Setup
    \brief  この関数は、割り当てられたWOLFSSL_CTXオブジェクトを解放します。
    この関数はCTX参照数を減らし、参照カウントが0に達したときにのみコンテキストを解放します。
    \return なし
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_free(ctx);
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
void wolfSSL_CTX_free(WOLFSSL_CTX*);

/*!
    \ingroup Setup
    \brief  この関数は割り当てられたWOLFSSLオブジェクトを解放します。
    \return なし
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL* ssl = 0;
    ...
    wolfSSL_free(ssl);
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_CTX_free
*/
void wolfSSL_free(WOLFSSL*);

/*!
    \ingroup TLS
    \brief  この関数は、引数sslのSSLセッションに対してアクティブなSSL/TLS接続をシャットダウンします。
    この関数は、ピアに"Close Notify"アラートを送信しようとします。
    呼び出し側アプリケーションは、Peerがその"Close Notify"アラートを応答として送信してくるのを待つか、
    またはwolfSSL_shutdownから呼び出しが戻った時点で（リソースを保存するために）下層の接続を切断するのを待つことができます。
    どちらのオプションもTLS仕様で許されています。シャットダウンした後に下層の接続を再び別のセッションで使用する予定ならば、ピア間で同期を保つために完全な2方向のシャットダウン手順を実行する必要があります。
    wolfSSL_shutdown()は、ブロックとノンブロッキングI/Oの両方で動作します。
    下層のI/Oがノンブロッキングの場合、wolfSSL_shutdown()が要求を満たすことができなかった場合、wolfSSL_shutdown()はエラーを返します。
    この場合、wolfSSL_get_error()への呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを生成します。
    その結果、下層のI/Oが準備ができたら、呼び出し側プロセスはwolfSSL_shutdown()への呼び出しを繰り返す必要があります。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_SHUTDOWN_NOT_DONE  シャットダウンが終了していない場合に返され、関数を再度呼び出す必要があります。
    \return SSL_FATAL_ERROR  失敗したときに返されます。より具体的なエラーコードはwolfSSL_get_error()を呼び出します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_shutdown(ssl);
    if (ret != 0) {
	    // failed to shut down SSL connection
    }
    \endcode
    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
int  wolfSSL_shutdown(WOLFSSL*);

/*!
    \ingroup IO
    \brief  この関数は、書き込み操作のために指定されたフラグを使用してバッファあるいはデータから、SSL接続に対して、szバイトを書き込みます。
    必要に応じて、wolfSSL_send()の呼び出し時点ではまだwolfSSL_connect()またはwolfSSL_accept()がまだ呼び出されていない場合、SSL/TLSセッションをネゴシエートします。
    wolfSSL_send()は、ブロックとノンブロッキングI/Oの両方で動作します。
    基礎となる入出力がノンブロッキングに設定されている場合、wolfSSL_send()が要求を満たすことができなかったらwolfSSL_send()は関数呼び出しからすぐに戻ります。
    この場合、wolfSSL_get_error()の呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを返します。
    その結果、基礎となるI/Oが準備ができたら、呼び出し側プロセスはwolfSSL_send()への呼び出しを繰り返す必要があります。
    基礎となる入出力がブロックされている場合、wolfSSL_send()は、サイズSZのバッファデータが完全に書かれたかエラーが発生したら、戻るだけです。

    \return 成功時には書き込んだバイト数（1以上）を返します。
    \return 0  失敗したときに返されます。特定のエラーコードについてwolfSSL_get_error()を呼び出します。
    \return SSL_FATAL_ERROR  エラーが発生したとき、または非ブロッキングソケットを使用するときには、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが受信され、再度WOLFSSL_WRITE()を呼び出す必要がある場合は、障害が発生します。特定のエラーコードを取得するには、wolfSSL_get_error()を使用してください。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param data  ピアに送信されるデータを含んでいるバッファへのポインタ。
    \param sz 送信データを含んでいるバッファのサイズ
    \param flags 下層のI/Oのsendに対して指定するフラグ


    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags = ... ;
    ...

    input = wolfSSL_send(ssl, msg, msgSz, flags);
    if (input != msgSz) {
    	// wolfSSL_send() failed
    }
    \endcode
    \sa wolfSSL_write
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags);

/*!
    \ingroup IO
    \brief  この関数は、基礎となるRECV動作のために指定されたフラグを使用して、SSLセッション（ssl）内部読み取りバッファからszバイトをバッファデータに読み出します。
    読み取られたバイトは内部受信バッファから削除されます。
    この関数はwolfssl_read()と同じです。
    ただし、アプリケーションが基礎となる読み取り操作のRECVフラグを設定できることを許可します。
    必要に応じてwolfssl_recv()がwolfssl_connect()またはwolfssl_accept()によってハンドシェイクがまだ実行されていない場合は、SSL/TLSセッションをネゴシエートします。
    SSL/TLSプロトコルは、最大サイズのSSLレコードを使用します（最大レコードサイズは<wolfssl_root> /wolfssl/internal.h）。
    そのため、wolfSSLは、レコードを処理および復号することができる前に、SSLレコード全体を内部的に読み取る必要があります。
    このため、wolfSSL_recv()への呼び出しは、呼び出し時に復号された最大バッファサイズを返すことができるだけです。
    wolfSSL_recv()への次の呼び出しで検索および復号される内部wolfSSL受信バッファで待機していない追加の復号化されたデータがあるかもしれません。
    引数szが内部読み取りバッファ内のバイト数よりも大きい場合、wolfSSL_recv()は内部読み取りバッファで使用可能なバイトを返します。
    バイトが内部読み取りバッファにバッファされていない場合は、wolfSSL_recv()への呼び出しは次のレコードの処理をトリガーします。
    \return 成功時には読み取られたバイト数(1以上)を返します。
    \return 0  失敗したときに返されます。これは、クリーン（通知アラートを閉じる）シャットダウンまたはピアが接続を閉じただけであることによって発生する可能性があります。特定のエラーコードについてwolfSSL_get_error()を呼び出します。
    \return SSL_FATAL_ERROR  エラーが発生した場合、または非ブロッキングソケットを使用するときには、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが発生し、アプリケーションが再びWOLFSSL_RECV()を呼び出す必要があります。特定のエラーコードを取得するには、wolfSSL_get_error()を使用してください。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param data  wolfSSL_recv()がデータを読み取るバッファー。
    \param sz  データを読み込むためのバイト数。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    int flags = ... ;
    ...

    input = wolfSSL_recv(ssl, reply, sizeof(reply), flags);
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }
    \endcode
    \sa wolfSSL_read
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
int  wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags);

/*!
    \ingroup Debug
    \brief  この関数は、直前のAPI関数呼び出し（wolfssl_connect、wolfssl_accept、wolfssl_read、wolfssl_writeなど）がエラーコード（SSL_FAILURE）を呼び出した理由を表す一意のエラーコードを返します。
    直前の関数の戻り値は、retを介してwolfSSL_get_errorに渡されます。wolfSSL_get_errorは一意のエラーコードを返します。
    wolfSSL_err_error_string()を呼び出して人間が読めるエラー文字列を取得することができます。
    詳細については、wolfSSL_err_error_string()を参照してください。

    \return 呼び出し成功時、この関数は、直前の関数が失敗した理由を説明する固有のエラーコードを返します。
    \return SSL_ERROR_NONE  引数retが0より大きい場合に返されます。retが0以下の場合、直前のAPIがエラーコードを返すが実際に発生しなかった場合にこの値を返す場合があります。
    例としては、引数szに0を渡してwolfSSL_read()を呼び出す場合に発生します。
    wolfssl_read()が0を戻した場合は通常エラーを示しますが、この場合はエラーは発生していません。
    従って、wolfSSL_get_error()がその後呼び出された場合、ssl_error_noneが返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
int  wolfSSL_get_error(WOLFSSL* ssl, int ret);

/*!
    \ingroup IO
    \brief  この関数はアラート履歴を取得します。
    \return SSL_SUCCESS  関数が正常に完了したときに返されます。警告履歴があったか、またはいずれにも、戻り値はSSL_SUCCESSです。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param h WOLFSSL構造体の"alert_history member" の値が格納される、WOLFSSL_ALERT_HISTORY構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_ALERT_HISTORY* h;
    ...
    wolfSSL_get_alert_history(ssl, h);
    // h now has a copy of the ssl->alert_history  contents
    \endcode
    \sa wolfSSL_get_error
*/
int  wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h);

/*!
    \ingroup Setup
    \brief  この関数は、SSLオブジェクトSSLがSSL/TLS接続を確立する目的で使用するセッションを設定します。
    セッション再開を行う場合、wolfSSL_shutdown()を呼び出す前にwolfSSL_get1_session()を呼び出してセッションオブジェクトを取得し、セッションIDを保存しておく必要があります。
    後で、アプリケーションは新しいWOLFSSLオブジェクトを作成し、保存したセッションをwolfSSL_set_session()に渡す必要があります。
    その後アプリケーションはwolfSSL_connect()を呼び出し、wolfSSLはセッション再開を試みます。
    wolfSSLサーバーコードでは、デフォルトでセッション再開を許可します。
    wolfSSL_get1_session()によって返されたオブジェクトは、アプリケーションが使用後に解放する必要があります。

    \return SSL_SUCCESS  セッションを正常に設定すると返されます。
    \return SSL_FAILURE  失敗した場合に返されます。これはセッションキャッシュが無効になっている、またはセッションがタイムアウトした場合によって発生する可能性があります。
    \return OPENSSL_EXTRAとWOLFSSL_ERROR_CODE_OPENSSLが定義されている場合には、セッションがタイムアウトしていてもSSL_SUCCESSが返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param session WOLFSSL_SESSION構造体へのポインタ。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get1_session(ssl);
    if (session == NULL) {
        // failed to get session object from ssl object
    }
    ...
    ret = wolfSSL_set_session(ssl, session);
    if (ret != SSL_SUCCESS) {
    	// failed to set the SSL session
    }
    wolfSSL_SESSION_free(session);
    ...
    \endcode
    \sa wolfSSL_get1_session
*/
int        wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session);

/*!
    \ingroup IO
    \brief  NO_SESSION_CACHE_REFが定義されている場合、この関数はSSLで使用されている現在のセッション（WOLFSSL_SESSION）へのポインタを返します。
    この関数は、WOLFSSL_SESSIONオブジェクトへの永続的なポインタを返します。
    返されるポインタは、wolfSSL_freeが呼び出されたときに解放されます。
    この呼び出しは、現在のセッションを検査または変更するためにのみ使用されます。
    セッション再開に使用する場合は、wolfSSL_get1_session()を使用することをお勧めします。
    NO_SESSION_CACHE_REFが定義されていない場合の後方互換性のために、この関数はローカルキャッシュに格納されている永続セッションオブジェクトポインタを返します。
    キャッシュサイズは有限であり、アプリケーションがwolfSSL_set_session()を呼び出す時までにセッションオブジェクトが別のSSL接続によって上書きされる危険性があります。
    アプリケーションにNO_SESSION_CACHE_REFを定義し、セッション再開にwolfSSL_get1_session()を使用することをお勧めします。

    \return 現在のSSLセッションオブジェクトへのポインタを返します。
    \return NULL  sslがNULLの場合、SSLセッションキャッシュが無効になっている場合、wolfSSLはセッションIDを使用できない、またはミューテックス関数が失敗した場合に返されます。

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get_session(ssl);
    if (session == NULL) {
	    // failed to get session pointer
    }
    ...
    \endcode
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この機能は、期限切れになったセッションキャッシュからセッションをフラッシュします。
    時間比較には引数tmが使用されます。
    wolfSSLは現在セッションに静的テーブルを使用しているため、フラッシングは不要です。
    そのため、この機能は現在スタブとして存在しています。
    この関数は、wolfsslがOpenSSL互換層でコンパイルされているときのOpenSSL互換性（ssl_flush_sessions）を提供します。

    \return なし
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param tm セッションの有効期限の比較で使用される時間

    _Example_
    \code
    WOLFSSL_CTX* ssl;
    ...
    wolfSSL_flush_sessions(ctx, time(0));
    \endcode
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
void       wolfSSL_flush_sessions(WOLFSSL_CTX* ctx, long tm);

/*!
    \ingroup TLS
    \brief  この関数はクライアントセッションをサーバーIDと関連付けます。引数newSessionがオンの場合、既存のセッションは再利用されません。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  引数sslまたは引数idがNULLの場合、または引数lenがゼロ以下の場合に返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param id  WOLFSSL_SESSION構造体のServerIDメンバーにコピーされるサーバーIDデータへのポインタ。
    \param len  サーバーIDデータのサイズ
    \param newSession セッションを再利用するか否かを指定するフラグ。オンの場合、既存のセッションは再利用されません。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    const byte id[MAX_SIZE];  // or dynamically create space
    int len = 0; // initialize length
    int newSession = 0; // flag to allow
    …
    int ret = wolfSSL_SetServerID(ssl, id, len, newSession);

    if (ret == WOLFSSL_SUCCESS) {
	    // The Id was successfully set
    }
    \endcode
    \sa wolfSSL_set_session
*/
int        wolfSSL_SetServerID(WOLFSSL* ssl, const unsigned char* id,
                                         int len, int newSession);

/*!
    \ingroup IO
    \brief  この関数は、WOLFSSL構造体の指定セッションインデックス値を取得します。
    \return この関数は、WOLFSSL構造体内のSessionIndexを表すint型の値を返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int sesIdx = wolfSSL_GetSessionIndex(ssl);

    if(sesIdx < 0 || sesIdx > sizeof(ssl->sessionIndex)/sizeof(int)){
    	// You have an out of bounds index number and something is not right.
    }
    \endcode
    \sa wolfSSL_GetSessionAtIndex
*/
int wolfSSL_GetSessionIndex(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数はセッションキャッシュの指定されたインデックスのセッションを取得し、それをメモリにコピーします。
    WOLFSSL_SESSION構造体はセッション情報を保持します。
    \return SSL_SUCCESS  関数が正常に実行され、エラーがスローされなかった場合に返されます。
    \return BAD_MUTEX_E  アンロックまたはロックミューテックスエラーが発生した場合に返されます。
    \return SSL_FAILURE  関数が正常に実行されなかった場合に返されます。
    \param idx  セッションインデックス値
    \param session WOLFSSL_SESSION構造体へのポインタ

    _Example_
    \code
    int idx; // The index to locate the session.
    WOLFSSL_SESSION* session;  // Buffer to copy to.
    ...
    if(wolfSSL_GetSessionAtIndex(idx, session) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode
    \sa UnLockMutex
    \sa LockMutex
    \sa wolfSSL_GetSessionIndex
*/
int wolfSSL_GetSessionAtIndex(int index, WOLFSSL_SESSION* session);

/*!
    \ingroup IO
    \brief  WOLFSSL_SESSION構造体からピア証明書チェーンを返します。
    \param session WOLFSSL_SESSION構造体へのポインタ

    _Example_
    \code
    WOLFSSL_SESSION* session;
    WOLFSSL_X509_CHAIN* chain;
    ...
    chain = wolfSSL_SESSION_get_peer_chain(session);
    if(!chain){
    	// There was no chain. Failure case.
    }
    \endcode
    \sa wolfSSL_GetSessionAtIndex
    \sa wolfSSL_GetSessionIndex
    \sa AddSession
*/

    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);

/*!
    \ingroup Setup
    \brief  この関数はリモートピアの検証方法を設定し、また証明書検証コールバック関数をSSLコンテキストに登録することもできます。
    検証コールバックは、検証障害が発生した場合にのみ呼び出されます。
    検証コールバックが必要な場合は、NULLポインタをverify_callbackに使用できます。
    ピア証明書の検証モードは、論理的またはフラグのリストです。
    可能なフラグ値は次のとおりです:<br>
    SSL_VERIFY_NONE<br>
     -クライアントモード：クライアントはサーバーから受信した証明書を検証せず、ハンドシェイクは通常どおり続きます。<br>
     -サーバーモード：サーバーはクライアントに証明書要求を送信しません。そのため、クライアント検証は有効になりません。<br>
    SSL_VERIFY_PEER<br>
     -クライアントモード：クライアントはハンドシェイク中にサーバーから受信した証明書を検証します。これはwolfSSLではデフォルトでオンにされます。したがって、このオプションを使用すると効果がありません。<br>
     -サーバーモード：サーバーは証明書要求をクライアントに送信し、受信したクライアント証明書を確認します。<br>
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT<br>
     -クライアントモード：クライアント側で使用されていない場合は効果がありません。<br>
     -サーバーモード：要求されたときにクライアントが証明書の送信に失敗した場合は、サーバー側で検証が失敗します（SSLサーバーのSSL_VERIFY_PEERを使用する場合）。<br>
    SSL_VERIFY_FAIL_EXCEPT_PSK<br>
     -クライアントモード：クライアント側で使用されていない場合は効果がありません。<br>
     -サーバーモード：PSK接続の場合を除き、検証はSSL_VERIFY_FAIL_IF_NO_PEER_CERTと同じです。 PSK接続が行われている場合、接続はピア証明書なしで通過します。<br>

    \return なし

    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param mode ピアの証明書をどのように検証するかを示すフラグ値
    \param verify_callback 証明書検証が失敗した際に呼び出されるコールバック関数。必要がないならNULLを指定すること。

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    wolfSSL_CTX_set_verify(ctx, (WOLFSSL_VERIFY_PEER |
                           WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT), NULL);
    \endcode
    \sa wolfSSL_set_verify
*/
void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode,
                                      VerifyCallback verify_callback);

/*!
    \ingroup Setup
    \brief  この関数はリモートピアの検証方法を設定し、また証明書検証コールバック関数をWOLFSSLオブジェクトに登録することもできます。
    検証コールバックは、検証障害が発生した場合にのみ呼び出されます。
    検証コールバックが必要な場合は、NULLポインタをverify_callbackに使用できます。
    ピア証明書の検証モードは、論理的またはフラグのリストです。
    可能なフラグ値は次のとおりです:<br>
    SSL_VERIFY_NONE<br>
     -クライアントモード：クライアントはサーバーから受信した証明書を検証せず、ハンドシェイクは通常どおり続きます。<br>
     -サーバーモード：サーバーはクライアントに証明書要求を送信しません。そのため、クライアント検証は有効になりません。<br>
    SSL_VERIFY_PEER<br>
     -クライアントモード：クライアントはハンドシェイク中にサーバーから受信した証明書を検証します。これはwolfSSLではデフォルトでオンにされます。したがって、このオプションを使用すると効果がありません。<br>
     -サーバーモード：サーバーは証明書要求をクライアントに送信し、受信したクライアント証明書を確認します。<br>
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT<br>
     -クライアントモード：クライアント側で使用されていない場合は効果がありません。<br>
     -サーバーモード：要求されたときにクライアントが証明書の送信に失敗した場合は、サーバー側で検証が失敗します（SSLサーバーのSSL_VERIFY_PEERを使用する場合）。<br>
    SSL_VERIFY_FAIL_EXCEPT_PSK<br>
     -クライアントモード：クライアント側で使用されていない場合は効果がありません。<br>
     -サーバーモード：PSK接続の場合を除き、検証はSSL_VERIFY_FAIL_IF_NO_PEER_CERTと同じです。 PSK接続が行われている場合、接続はピア証明書なしで通過します。<br>

    \return なし

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param mode ピアの証明書をどのように検証するかを示すフラグ値
    \param verify_callback 証明書検証が失敗した際に呼び出されるコールバック関数。必要がないならNULLを指定すること。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    \endcode
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback verify_callback);

/*!
    \ingroup CertsKeys
    \brief  この関数は、検証コールバックのためのユーザーCTXオブジェクト情報を格納します。
    \return なし

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param ctx ボイドポインタ。WOLFSSL構造体のverifyCbCtx メンバーにセットされます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    (void*)ctx;
    ...
    if(ssl != NULL){
    wolfSSL_SetCertCbCtx(ssl, ctx);
    } else {
	    // Error case, the SSL is not initialized properly.
    }
    \endcode
    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx);

/*!
    \ingroup CertsKeys
    \brief  この関数は、検証コールバックのためのユーザーCTXオブジェクト情報を格納します。
    \return なし
    \param ctx  WOLFSSL_CTX構造体へのポインタ。
    \param ctx ボイドポインタ。WOLFSSL_CTX構造体のverifyCbCtx メンバーにセットされます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    void* userCtx = NULL; // Assign some user defined context
    ...
    if(ctx != NULL){
        wolfSSL_SetCertCbCtx(ctx, userCtx);
    } else {
        // Error case, the SSL is not initialized properly.
    }
    \endcode
    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx);

/*!
    \ingroup IO
    \brief  この関数は、wolfSSL_read()によって読み取られるWOLFSSLオブジェクトでバッファされているバイト数を返します。
    \return この関数は、保留中のバイト数を返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    int pending = 0;
    WOLFSSL* ssl = 0;
    ...

    pending = wolfSSL_pending(ssl);
    printf(“There are %d bytes buffered and available for reading”, pending);
    \endcode
    \sa wolfSSL_recv
    \sa wolfSSL_read
    \sa wolfSSL_peek
*/
int  wolfSSL_pending(WOLFSSL*);

/*!
    \ingroup Debug
    \brief  この機能はOpenSSL API（SSL_load_error_string）との互換性の目的みで提供してあり処理は行いません。
    \return なし
    \param なし

    _Example_
    \code
    wolfSSL_load_error_strings();
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
void wolfSSL_load_error_strings(void);

/*!
    \ingroup TLS
    \brief  この関数はwolfSSL_CTX_new()内で内部的に呼び出されます。
    この関数はwolfSSL_Init()のラッパーで、wolfSSLがOpenSSL互換層でコンパイルされたときのOpenSSL　API（ssl_library_init）との互換性の為に存在します。
    wolfSSL_init()は、より一般的に使用されているwolfSSL初期化機能です。

    \return SSL_SUCCESS  成功した場合に返されます。に返されます。
    \return SSL_FATAL_ERROR  失敗したときに返されます。

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_library_init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL
    }
    ...
    \endcode
    \sa wolfSSL_Init
    \sa wolfSSL_Cleanup
*/
int  wolfSSL_library_init(void);

/*!
    \brief この関数はWOLFSSLオブジェクトレベルでDevice Idをセットします。
    \return WOLFSSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  sslがNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param devId ハードウエアと共に使用する際に指定するID

    _Example_
    \code
    WOLFSSL* ssl;
    int DevId = -2;

    wolfSSL_SetDevId(ssl, devId);

    \endcode
    \sa wolfSSL_CTX_SetDevId
    \sa wolfSSL_CTX_GetDevId
*/
int wolfSSL_SetDevId(WOLFSSL* ssl, int devId);

/*!
    \brief この関数はWOLFSSL_CTXレベルでDevice Idをセットします。

    \return WOLFSSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  sslがNULLの場合に返されます。

    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param devId ハードウエアと共に使用する際に指定するID

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int DevId = -2;

    wolfSSL_CTX_SetDevId(ctx, devId);

    \endcode
    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_GetDevId
*/
int wolfSSL_CTX_SetDevId(WOLFSSL_CTX* ctx, int devId);

/*!
    \brief この関数はWOLFSSL_CTXレベルでDevice Idを取得します。
    \return devId  成功時に返されます。
    \return INVALID_DEVID  SSLとCTXの両方がNULLの場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx;

    wolfSSL_CTX_GetDevId(ctx, ssl);

    \endcode
    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_SetDevId
*/
int wolfSSL_CTX_GetDevId(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数はSSLセッションキャッシュ機能を有効または無効にします。
    動作はモードに使用される値によって異なります。
    モードの値は次のとおりです：
    SSL_SESS_CACHE_OFF  - セッションキャッシングを無効にします。デフォルトでセッションキャッシングがオンになっています。
    SSL_SESS_CACHE_NO_AUTO_CLEAR  - セッションキャッシュのオートフラッシュを無効にします。デフォルトで自動フラッシングはオンになっています。

    \return SSL_SUCCESS  成功に戻ります。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param mode セッションキャッシュの振る舞いを変更する為に使用します。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (ret != SSL_SUCCESS) {
    	// failed to turn SSL session caching off
    }
    \endcode
    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_timeout
*/
long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX* ctx, long mode);

/*!
    \brief  この関数はセッションシークレットコールバック関数をセットします。
    SessionSecretCbタイプは次のシグネチャとなっています：int（* sessioneCretcb）（wolfssl * ssl、void * secret、int * secretsz、void * ctx）。
    WOLFSSL構造体のsessionSecretCbメンバーは引数cbに設定されます。
    \return SSL_SUCCESS  関数の実行がエラーを返されなかった場合に返されます。
    \return SSL_FATAL_ERROR  WOLFSSL構造がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param cb セッションシークレットコールバック関数ポインタ。
    \param ctx セッションシークレットコールバック関数に渡されるユーザーコンテキスト。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    // Signature of SessionSecretCb
    int SessionSecretCB (WOLFSSL* ssl, void* secret, int* secretSz,
    void* ctx) = SessionSecretCb;
    …
    int wolfSSL_set_session_secret_cb(ssl, SessionSecretCB, (void*)ssl->ctx){
	    // Function body.
    }
    \endcode
    \sa SessionSecretCb
*/
int  wolfSSL_set_session_secret_cb(WOLFSSL* ssl, SessionSecretCb cb, void* ctx);

/*!
    \ingroup IO
    \brief  この関数はセッションキャッシュをファイルに持続します。追加のメモリ使用のため、memsaveは使用されません。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。セッションキャッシュはファイルに書き込まれました。
    \return SSL_BAD_FILE  FNAMEを開くことができないか、それ以外の場合は破損した場合に返されます。
    \return FWRITE_ERROR  XfWriteがファイルへの書き込みに失敗した場合に返されます。
    \return BAD_MUTEX_E  ミューテックスロック障害が発生した場合に返されます。
    \param fname 書き込み対象ファイル名へのポインタ。

    _Example_
    \code
    const char* fname;
    ...
    if(wolfSSL_save_session_cache(fname) != SSL_SUCCESS){
    	// Fail to write to file.
    }
    \endcode
    \sa XFWRITE
    \sa wolfSSL_restore_session_cache
    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_save_session_cache(const char* fname);

/*!
    \ingroup IO
    \brief  この関数はファイルから永続セッションキャッシュを復元します。追加のメモリ使用のため、memstoreは使用しません。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return SSL_BAD_FILE  関数に渡されたファイルが破損していてXFOPENによって開くことができなかった場合に返されます。
    \return FREAD_ERROR  ファイルにXFREADから読み取りエラーが発生した場合に返されます。
    \return CACHE_MATCH_ERROR  セッションキャッシュヘッダの一致が失敗した場合に返されます。
    \return BAD_MUTEX_E  ミューテックスロック障害が発生した場合に返されます。
    \param fname キャシュを読み取るためのファイル名へのポインタ。


    _Example_
    \code
    const char *fname;
    ...
    if(wolfSSL_restore_session_cache(fname) != SSL_SUCCESS){
        // Failure case. The function did not return SSL_SUCCESS.
    }
    \endcode
    \sa XFREAD
    \sa XFOPEN
*/
int  wolfSSL_restore_session_cache(const char* fname);

/*!
    \ingroup IO
    \brief  この関数はセッションキャッシュをメモリに保持します。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。セッションキャッシュはメモリに正常に永続化されました。
    \return BAD_MUTEX_E  ミューテックスロックエラーが発生した場合に返されます。
    \return BUFFER_E  バッファサイズが小さすぎると返されます。
    \param mem  セッションキャッシュのコピー先バッファへのポインタ
    \param sz コピー先バッファのサイズ

    _Example_
    \code
    void* mem;
    int sz; // Max size of the memory buffer.
    …
    if(wolfSSL_memsave_session_cache(mem, sz) != SSL_SUCCESS){
    	// Failure case, you did not persist the session cache to memory
    }
    \endcode
    \sa XMEMCPY
    \sa wolfSSL_get_session_cache_memsize
*/
int  wolfSSL_memsave_session_cache(void* mem, int sz);

/*!
    \ingroup IO
    \brief  この関数はメモリから永続セッションキャッシュを復元します。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return BUFFER_E  メモリバッファが小さすぎると返されます。
    \return BAD_MUTEX_E  セッションキャッシュミューテックスロックが失敗した場合に返されます。
    \return CACHE_MATCH_ERROR  セッションキャッシュヘッダの一致が失敗した場合に返されます。
    \param mem  セッションキャッシュを保持しているバッファへのポインタ。
    \param sz バッファのサイズ

    _Example_
    \code
    const void* memoryFile;
    int szMf;
    ...
    if(wolfSSL_memrestore_session_cache(memoryFile, szMf) != SSL_SUCCESS){
    	// Failure case. SSL_SUCCESS was not returned.
    }
    \endcode
    \sa wolfSSL_save_session_cache
*/
int  wolfSSL_memrestore_session_cache(const void* mem, int sz);

/*!
    \ingroup IO
    \brief  この関数は、セッションキャッシュ保存バッファをどのように大きくするかを返します。
    \return この関数は、セッションキャッシュ保存バッファのサイズを表す整数を返します。

    _Example_
    \code
    int sz = // Minimum size for error checking;
    ...
    if(sz < wolfSSL_get_session_cache_memsize()){
        // Memory buffer is too small
    }
    \endcode
    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_get_session_cache_memsize(void);

/*!
    \ingroup CertsKeys
    \brief  この関数はCertキャッシュをメモリからファイルに書き込みます。
    \return SSL_SUCCESS  CM_SaveCertCacheが正常に終了した場合。
    \return BAD_FUNC_ARG  引数のいずれかの引数がNULLの場合に返されます。
    \return SSL_BAD_FILE  証明書キャッシュ保存ファイルを開くことができなかった場合。
    \return BAD_MUTEX_E  ロックミューテックスが失敗した場合
    \return MEMORY_E  メモリの割り当てに失敗しました。
    \return FWRITE_ERROR  証明書キャッシュファイルの書き込みに失敗しました。
    \param ctx  WOLFSSL_CTX構造体へのポインタ、証明書情報を保持します。
    \param fname  出力先ファイル名へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    const char* fname;
    ...
    if(wolfSSL_CTX_save_cert_cache(ctx, fname)){
	    // file was written.
    }
    \endcode
    \sa CM_SaveCertCache
    \sa DoMemSaveCertCache
*/
int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys
    \brief  この関数はファイルから証明書キャッシュを担当します。
    \return SSL_SUCCESS 正常に実行された場合に返されます。
    \return SSL_BAD_FILE  XFOPENがXBADFILEを返すと返されます。ファイルが破損しています。
    \return MEMORY_E  TEMPバッファの割り当てられたメモリが失敗した場合に返されます。
    \return BAD_FUNC_ARG  引数fnameまたは引数ctxがNULLである場合に返されます。
    \param ctx  WOLFSSL_CTX構造体へのポインタ、証明書情報を保持します。
    \param fname 証明書キャッシュを読み取るファイル名へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* fname = "path to file";
    ...
    if(wolfSSL_CTX_restore_cert_cache(ctx, fname)){
    	// check to see if the execution was successful
    }
    \endcode
    \sa CM_RestoreCertCache
    \sa XFOPEN
*/
int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys
    \brief  この関数は証明書キャッシュをメモリに持続します。
    \return SSL_SUCCESS  機能の実行に成功したことに戻ります。エラーが投げられていません。
    \return BAD_MUTEX_E  WOLFSSL_CERT_MANAGER構造体のcaLockメンバー0（ゼロ）ではなかった。
    \return BAD_FUNC_ARG  引数ctx、memがNULLの場合、またはszが0以下の場合に返されます。
    \return BUFFER_E  出力バッファMEMが小さすぎました。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param mem  宛先へのvoidポインタ（出力バッファ）。
    \param sz  出力バッファのサイズ。
    \param used 証明書キャッシュヘッダーのサイズを格納する変数へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol );
    void* mem;
    int sz;
    int* used;
    ...
    if(wolfSSL_CTX_memsave_cert_cache(ctx, mem, sz, used) != SSL_SUCCESS){
	    // The function returned with an error
    }
    \endcode
    \sa DoMemSaveCertCache
    \sa GetCertCacheMemSize
    \sa CM_MemRestoreCertCache
    \sa CM_GetCertCacheMemSize
*/
int  wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem, int sz, int* used);

/*!
    \ingroup Setup
    \brief  この関数は証明書キャッシュをメモリから復元します。
    \return SSL_SUCCESS  関数とサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  CTXまたはMEMパラメータがNULLまたはSZパラメータがゼロ以下の場合に返されます。
    \return BUFFER_E  CERTキャッシュメモリバッファが小さすぎると戻ります。
    \return CACHE_MATCH_ERROR  CERTキャッシュヘッダーの不一致があった場合に返されます。
    \return BAD_MUTEX_E  ロックミューテックスが失敗した場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param mem  証明書キャッシュに復元される値を保持しているバッファへのポインタ。
    \param sz バッファのサイズ

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    void* mem;
    int sz = (*int) sizeof(mem);
    …
    if(wolfSSL_CTX_memrestore_cert_cache(ssl->ctx, mem, sz)){
    	// The success case
    }
    \endcode
    \sa CM_MemRestoreCertCache
*/
int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz);

/*!
    \ingroup CertsKeys
    \brief  Certificate Cache Saveバッファが必要なサイズを返します。
    \return メモリサイズを返します。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がNULLの場合に返されます。
    \return BAD_MUTEX_E ミューテックスロックエラーが発生した場合に返されます。

    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol);
    ...
    int certCacheSize = wolfSSL_CTX_get_cert_cache_memsize(ctx);

    if(certCacheSize != BAD_FUNC_ARG || certCacheSize != BAD_MUTEX_E){
	// Successfully retrieved the memory size.
    }
    \endcode
    \sa CM_GetCertCacheMemSize
*/
int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief  この関数は、与えられたWOLFSSL_CTXに暗号スイートリストを設定します。
    この暗号スイートリストは、このコンテキストを使用して作成された新しいSSLセッション（WolfSSL）のデフォルトリストになります。
    リスト内の暗号は、優先度の高いものの順に順にソートされるべきです。
    wolfSSL_CTX_set_cipher_list()が呼び出される都度、特定のSSLコンテキストの暗号スイートリストを提供されたリストにリセットします。
    暗号スイートリストはヌル終端されたコロン区切りリストです。
    たとえば、リストの値が「DHE-RSA-AES256-SHA256：DHE-RSA-AES128-SHA256：AES256-SHA256」有効な暗号値は、src/internal.cのcipher_names []配列のフルネーム値です。
    （有効な暗号化値の明確なリストの場合はsrc/internal.cをチェックしてください）

    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  失敗した場合に返されます。

    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param list ヌル終端されたコロン区切りの暗号スイートリスト文字列へのポインタ。


    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_cipher_list(ctx,
    “DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256”);
    if (ret != SSL_SUCCESS) {
    	// failed to set cipher suite list
    }
    \endcode
    \sa wolfSSL_set_cipher_list
    \sa wolfSSL_CTX_new
*/
int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);

/*!
    \ingroup Setup
    \brief  この関数は、特定のWolfSSLオブジェクト（SSLセッション）の暗号スイートリストを設定します。
    この暗号スイートリストは、このコンテキストを使用して作成された新しいSSLセッション（WolfSSL）のデフォルトリストになります。
    リスト内の暗号は、優先度の高いものの順に順にソートされるべきです。
    wolfSSL_CTX_set_cipher_list()が呼び出される都度、特定のSSLコンテキストの暗号スイートリストを提供されたリストにリセットします。
    暗号スイートリストはヌル終端されたコロン区切りリストです。
    たとえば、リストの値が「DHE-RSA-AES256-SHA256：DHE-RSA-AES128-SHA256：AES256-SHA256」有効な暗号値は、src/internal.cのcipher_names []配列のフルネーム値です。
    （有効な暗号化値の明確なリストの場合はsrc/internal.cをチェックしてください）

    \return SSL_SUCCESS  機能完了に成功したときに返されます。
    \return SSL_FAILURE  失敗した場合に返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param list ヌル終端されたコロン区切りの暗号スイートリスト文字列へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_cipher_list(ssl,
    “DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256”);
    if (ret != SSL_SUCCESS) {
    	// failed to set cipher suite list
    }
    \endcode
    \sa wolfSSL_CTX_set_cipher_list
    \sa wolfSSL_new
*/
int  wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list);

/*!
    \brief  この関数はWOLFSSL DTLSオブジェクトに下層のUDP I/Oはノンブロッキングであることを通知します。
    アプリケーションがWOLFSSLオブジェクトを作成した後、ノンブロッキングUDPソケットを使用する場合は、wolfSSL_dtls_set_using_nonblock()を呼び出します。
    これにより、WOLFSSLオブジェクトは、recvfrom呼び出しがタイムアウトせずにEWOULDBLOCKを受信することを意味します。
    \return なし
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param nonblock WOLFSSL構造体にノンブロッキングI/Oを使用していることを指定するフラグ。ノンブロッキングを使用している場合には１を指定、それ以外は0を指定してください。


    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    \endcode
    \sa wolfSSL_dtls_get_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
void wolfSSL_dtls_set_using_nonblock(WOLFSSL* ssl, int nonblock);
/*!
    \brief  この関数はWOLFSSL DTLSオブジェクトが下層にUDPノンブロッキングI/Oを使用しているか否かを取得します。
    WOLFSSLオブジェクトがノンブロッキングI/Oを使用している場合、この関数は1を返します。
    これにより、WOLFSSLオブジェクトは、EWOULDBLOCKを受信することを意味します。
    この機能はDTLSセッションにとってのみ意味があります。
    \return 0  基礎となるI/Oがブロックされています。
    \return 1  基礎となるI/Oはノンブロッキングです。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_dtls_get_using_nonblock(ssl);
    if (ret == 1) {
    	// underlying I/O is non-blocking
    }
    ...
    \endcode
    \sa wolfSSL_dtls_set_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_using_nonblock
*/
int  wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl);
/*!
    \brief  この関数は現在のタイムアウト値を秒単位で返します。
    ノンブロッキングソケットを使用する場合、ユーザーコードでは、利用可能なrecvVデータの到着をチェックするタイミングや待つべき時間を知る必要があります。
    この関数によって返される値は、アプリケーションがどのくらい待機するかを示します。
    \return seconds  現在のDTLSタイムアウト値（秒）
    \return NOT_COMPILED_IN  wolfSSLがDTLSサポートで構築されていない場合。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    int timeout = 0;
    WOLFSSL* ssl;
    ...
    timeout = wolfSSL_get_dtls_current_timeout(ssl);
    printf(“DTLS timeout (sec) = %d\n”, timeout);
    \endcode
    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);

/*!
    \brief この関数はアプリケーションがより早いタイムアウト時間を設定する必要がある場合にtrueを返します。
    ノンブロッキングソケットを使用する場合でユーザーコードで受信データが到着しているか何時チェックするか、
    あるいはどのくらいの時間待てばよいのかを決める必要があります。
    この関数が true を返した場合、ライブラリはすでに通信の中断を検出しましたが、
    他のピアからのメッセージがまだ送信中の場合に備えて、もう少し待機する必要があることを意味します。
    このタイマーの値を微調整するのはアプリケーション次第ですが、dtls_get_current_timeout()/4が最適です。

    \return true アプリケーションがより早いタイムアウトを設定する必要がある場合に返されます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_set_send_more_acks
*/
int  wolfSSL_dtls13_use_quick_timeout(WOLFSSL *ssl);
/*!
  \ingroup Setup

    \brief この関数は、ライブラリが中断を検出したときにすぐに他のピアにACKを送信するかどうかを設定します。
    ACKをすぐに送信すると、遅延は最小限に抑えられますが、必要以上に多くの帯域幅が消費される可能性があります。
    アプリケーションが独自にタイマーを管理しており、このオプションが0に設定されている場合、
    アプリケーションコードはwolfSSL_dtls13_use_quick_timeout()を使用して、
    遅延したACKを送信するためにより速いタイムアウトを設定する必要があるかどうかを判断できます。

    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param value 設定を行う場合には１を行わない場合には0を設定します。

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_use_quick_timeout
*/
void  wolfSSL_dtls13_set_send_more_acks(WOLFSSL *ssl, int value);

/*!
    \ingroup Setup
    \brief  この関数はDTLSタイムアウトを設定します。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。SSLのDTLS_TIMEOUT_INITとDTLS_TIMEOUTメンバーが設定されています。
    \return BAD_FUNC_ARG  引数sslがNULLの場合、またはタイムアウトが0以下の場合に返されます。タイムアウト引数が許可されている最大値を超えている場合にも返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param value タイムアウトオプションを有効にする場合には1を指定し、無効にする場合には0を指定します。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUT;
    ...
    if(wolfSSL_dtls_set_timeout_init(ssl, timeout)){
    	// the dtls timeout was set
    } else {
    	// Failed to set DTLS timeout.
    }
    \endcode
    \sa wolfSSL_dtls_set_timeout_max
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int);

/*!
    \brief
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  wolfssl構造体がNULLの場合、またはTIMEOUT引数がゼロ以下である場合、またはWolfSSL構造体のDTLS_TIMEOUT_INITメンバーよりも小さい場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param timeout 最大タイムアウト時間

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUTVAL;
    ...
    int ret = wolfSSL_dtls_set_timeout_max(ssl);
    if(!ret){
    	// Failed to set the max timeout
    }
    \endcode
    \sa wolfSSL_dtls_set_timeout_init
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int);

/*!
    \brief  DTLSでノンブロッキングソケットを使用する場合、この関数は送信がタイムアウトしたと考えられる場合に呼び出される必要があります。
    タイムアウト値の調整など、最後の送信を再試行するために必要なアクションを実行します。 時間がかかりすぎると、失敗が返されます。

    \return SSL_SUCCESS  成功時に戻ります
    \return SSL_FATAL_ERROR  ピアからの応答を得ることなく、再送信/タイムアウトが多すぎる場合に返されます。
    \return NOT_COMPILED_IN wolfSSLがDTLSサポートでコンパイルされていない場合に返されます。

    _Example_
    \code
    See the following files for usage examples:
    <wolfssl_root>/examples/client/client.c
    <wolfssl_root>/examples/server/server.c
    \endcode
    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_got_timeout(WOLFSSL* ssl);

/*!
    \brief DTLSでノンブロッキングソケットを使用する場合、この関数は予想されるタイムアウト値と再送信回数を無視して最後のハンドシェイクフライトを再送信します。
    これは、DTLSを使用しており、タイムアウトや再試行回数も管理する必要があるアプリケーションに役立ちます。

    \return SSL_SUCCESS 成功時に戻ります
    \return SSL_FATAL_ERROR ピアからの応答が得られないまま再送信/タイムアウトが多すぎる場合に返されます。
    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls_retransmit(ssl);
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int wolfSSL_dtls_retransmit(WOLFSSL* ssl);

/*!
    \brief  DTLSを使用するように構成されているかどうかを取得します。
    \return 1  SSLセッション（SSL）がDTLSを使用するように設定されている場合、この関数は1を返します。
    \return 0  そうでない場合に返されます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls(ssl);
    if (ret) {
    	// SSL session has been configured to use DTLS
    }
    \endcode
    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls(WOLFSSL* ssl);

/*!
    \brief  この関数は引数peerで与えられるアドレスをDTLSのピアとしてセットします。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  失敗時に返されます。
    \return SSL_NOT_IMPLEMENTED  wolfSSLがDTLSをサポートするようにコンパイルされていない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param peer  ピアのアドレスを含むsockaddr_in構造体へのポインタ。
    \param peerSz sockaddr_in構造体のサイズ。0が指定された場合にはsslに設定されているピアの情報をクリアします。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to set DTLS peer
    }
    \endcode
    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz);

/*!
    \brief  この関数は、現在のDTLSピアのsockaddr_in(サイズpeerSz)を取得します。
    この関数は、peerSzをSSLセッションに保存されている実際のDTLSピアサイズと比較します。
    ピアアドレスがpeerに収まる場合は、peerSzがピアのサイズに設定されて、ピアのsockaddr_inがpeerにコピーされます。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  失敗時に返されます。
    \return SSL_NOT_IMPLEMENTED  wolfSSLがDTLSをサポートするようにコンパイルされていない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param peer  ピアのsockaddr_in構造体を保存するためのバッファへのポインタ。
    \param peerSz サイズを格納する変数。入力時には引数peerで示されるバッファのサイズを指定してください。出力時には実際のsockaddr_in構造体のサイズを返します。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_get_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to get DTLS peer
    }
    \endcode
    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz);

/*!
    \ingroup Debug
    \brief  この関数は、wolfSSL_get_error()によって返されたエラーコードをより人間が読めるエラー文字列に変換します。
    引数errNumberは、wolfSSL_get_error()によって返され、引数dataはエラー文字列が配置されるバッファへのポインタです。
    MAX_ERROR_SZで定義されているように、データの最大長はデフォルトで80文字です。
    これはwolfssl/wolfcrypt/error.hで定義されています。
    \return success  正常に完了すると、この関数はdataに返されるのと同じ文字列を返します。
    \return failure  失敗すると、この関数は適切な障害理由、MSGを持つ文字列を返します。
    \param errNumber  wolfSSL_get_error()によって返されたエラーコード。
    \param data 人間が読めるエラー文字列を格納したバッファへのポインタ

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data);

/*!
    \ingroup Debug
    \brief  この関数は、wolfssl_err_error_string()のバッファのサイズを指定するバージョンです。
    ここで、引数lenは引数bufに書き込まれ得る最大文字数を指定します。
    wolfSSL_err_error_string()と同様に、この関数はwolfSSL_get_error()から返されたエラーコードをより人間が読めるエラー文字列に変換します。
    人間が読める文字列はbufに置かれます。
    \return なし
    \param e  wolfSSL_get_error()によって返されたエラーコード。
    \param buff  eと一致する人間が読めるエラー文字列を含む出力バッファ。
    \param len 出力バッファのサイズ


    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string_n(err, buffer, 80);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long sz);

/*!
    \ingroup TLS
    \brief  この関数は、Options構造体のcloseNotifyまたはconnResetまたはsentNotifyメンバーのシャットダウン条件をチェックします。
    Options構造体はWOLFSSL構造体内にあります。
    \return 1  SSL_SENT_SHUTDOWNが返されます。
    \return 2  SSL_RECEIVED_SHUTDOWNが返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    int ret;
    ret = wolfSSL_get_shutdown(ssl);

    if(ret == 1){
	    SSL_SENT_SHUTDOWN
    } else if(ret == 2){
	    SSL_RECEIVED_SHUTDOWN
    } else {
	    Fatal error.
    }
    \endcode
    \sa wolfSSL_SESSION_free
*/
int  wolfSSL_get_shutdown(const WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は、オプション構造体の再開メンバを返します。フラグはセッションを再利用するかどうかを示します。そうでなければ、新しいセッションを確立する必要があります。
    \return This  関数セッションの再利用のフラグを表すオプション構造に保持されているint型を返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(!wolfSSL_session_reused(sslResume)){
	    // No session reuse allowed.
    }
    \endcode
    \sa wolfSSL_SESSION_free
    \sa wolfSSL_GetSessionIndex
    \sa wolfSSL_memsave_session_cache
*/
int  wolfSSL_session_reused(WOLFSSL* ssl);

/*!
    \ingroup TLS
    \brief  この関数は、接続が確立されているかどうかを確認します。
    \return 0  接続が確立されていない場合、すなわちWolfSSL構造体がNULLまたはハンドシェイクが行われていない場合に返されます。
    \return 1  接続が確立されていない場合は返されます.WolfSSL構造体はNULLまたはハンドシェイクが行われていません。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_is_init_finished(ssl)){
	    Handshake is done and connection is established
    }
    \endcode
    \sa wolfSSL_set_accept_state
    \sa wolfSSL_get_keys
    \sa wolfSSL_set_shutdown
*/
int  wolfSSL_is_init_finished(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  文字列として使用されているSSLバージョンを返します。
    \return "SSLv3"  SSLv3を使う
    \return "TLSv1"  TLSV1を使用する
    \return "TLSv1.1"  TLSV1.1を使用する
    \return "TLSv1.2"  TLSV1.2を使用する
    \return "TLSv1.3"  TLSV1.3を使用する
    \return "DTLS":  DTLSを使う
    \return "DTLSv1.2"  DTLSV1.2を使用する
    \return "unknown"  どのバージョンのTLSが使用されているかを判断するという問題がありました。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);
    printf(wolfSSL_get_version("Using version: %s", ssl));
    \endcode
    \sa wolfSSL_lib_version
*/
const char*  wolfSSL_get_version(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  SSLセッションで現在の暗号スイートを返します。
    \return ssl->options.cipherSuite  現在の暗号スイートを表す整数。
    \return 0  提供されているSSLセッションはNULLです。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_get_current_cipher_suite(ssl) == 0)
    {
        // Error getting cipher suite
    }
    \endcode
    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_list
*/
int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は、SSLセッションの現在の暗号へのポインタを返します。
    \return The  関数WolfSSL構造体の暗号メンバーのアドレスを返します。これはwolfssl_icipher構造へのポインタです。
    \return NULL  WolfSSL構造がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    WOLFSSL_CIPHER* cipherCurr = wolfSSL_get_current_cipher;

    if(!cipherCurr){
    	// Failure case.
    } else {
    	// The cipher was returned to cipherCurr
    }
    \endcode
    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は、SSLオブジェクト内のCipher Suiteと使用可能なスイートと一致し、文字列表現を返します。
    \return string  この関数は、一致した暗号スイートの文字列表現を返します。
    \return none  スイートが一致していない場合は「なし」を返します。
    \param cipher WOLFSSL_CIPHER構造体へのポインタ

    _Example_
    \code
    // gets cipher name in the format DHE_RSA ...
    const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl){
	WOLFSSL_CIPHER* cipher;
	const char* fullName;
    …
	cipher = wolfSSL_get_curent_cipher(ssl);
	fullName = wolfSSL_CIPHER_get_name(cipher);

	if(fullName){
		// sanity check on returned cipher
	}
    \endcode
    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
const char*  wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup IO
    \brief  この関数は、SSLオブジェクト内の暗号スイートと使用可能なスイートと一致します。
    \return This  関数Suiteが一致させたString値を返します。スイートが一致していない場合は「なし」を返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    #ifdef WOLFSSL_DTLS
    …
    // make sure a valid suite is used
    if(wolfSSL_get_cipher(ssl) == NULL){
	    WOLFSSL_MSG(“Can not match cipher suite imported”);
	    return MATCH_SUITE_ERROR;
    }
    …
    #endif // WOLFSSL_DTLS
    \endcode
    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
const char*  wolfSSL_get_cipher(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSL構造体からWOLFSSL_SESSIONを参照型として返します。
    これには、wolfSSL_SESSION_freeを呼び出してセッション参照を解除する必要があります。
    WOLFSSL_SESSIONは、セッションの再開を実行するために必要なすべての必要な情報を含み、新しいハンドシェイクなしで接続を再確立します。
    セッションの再開の場合、wolfSSL_shutdown()をセッションオブジェクトに呼び出す前に、アプリケーションはオブジェクトからwolfssl_get1_session()を呼び出して保存する必要があります。
    これはセッションへのポインタを返します。
    その後、アプリケーションは新しいWOLFSSLオブジェクトを作成し、保存したセッションをwolfssl_set_session()に割り当てる必要があります。
    この時点で、アプリケーションはwolfssl_connect()を呼び出し、WolfSSLはセッションを再開しようとします。
    WolfSSLサーバーコードでは、デフォルトでセッションの再開を許可します。
    wolfssl_get1_session()によって返されたオブジェクトは、アプリケーションが使用後は解放される必要があります。
    \return WOLFSSL_SESSION  成功の場合はセッションポインタを返します。
    \return NULL  sslがNULLの場合、SSLセッションキャッシュが無効になっている場合、WolfSSLはセッションIDを使用できない、またはミューテックス関数が失敗します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* ses;
    // attempt/complete handshake
    wolfSSL_connect(ssl);
    ses  = wolfSSL_get1_session(ssl);
    // check ses information
    // disconnect / setup new SSL instance
    wolfSSL_set_session(ssl, ses);
    // attempt/resume handshake
    wolfSSL_SESSION_free(ses);
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_SESSION_free
*/
WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  wolfsslv23_client_method()関数は、アプリケーションがクライアントであることを示すために使用され、SSL 3.0~TLS 1.3の間でサーバーでサポートされている最高のプロトコルバージョンをサポートします。この関数は、wolfSSL_CTX_new()を使用してSSL / TLSコンテキストを作成するときに使用される新しいWolfssl_method構造体のメモリを割り当てて初期化します。WolfSSLクライアントとサーバーの両方が堅牢なバージョンのダウングレード機能を持っています。特定のプロトコルバージョンメソッドがどちらの側で使用されている場合は、そのバージョンのみがネゴシエートされたり、エラーが返されます。たとえば、TLSV1を使用し、SSLv3のみに接続しようとするクライアントは、TLSV1.1に接続しても失敗します。この問題を解決するために、wolfsslv23_client_method()関数を使用するクライアントは、サーバーでサポートされている最高のプロトコルバージョンを使用し、必要に応じてSSLv3にダウングレードします。この場合、クライアントはSSLv3  -  TLSv1.3を実行しているサーバーに接続できるようになります。
    \return pointer  成功すると、wolfssl_methodへのポインタが返されます。
    \return Failure  xmallocを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがENOMEMに設定されます）。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;
    method = wolfSSLv23_client_method();
    if (method == NULL) {
	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD* wolfSSLv23_client_method(void);

/*!
    \ingroup IO
    \brief  この関数は、内部メモリバッファの先頭へのバイトポインタを設定するために使用されます。
    \return size  成功すると、バッファのサイズが返されます
    \return SSL_FATAL_ERROR  エラーケースに遭遇した場合
    \param bio  のメモリバッファを取得するためのWOLFSSL_BIO構造体。
    \param p メモリバッファへのポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    const byte* p;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_get_mem_data(bio, &p);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,void* p);

/*!
    \ingroup IO
    \brief  使用するBIOのファイル記述子を設定します。
    \return SSL_SUCCESS(1)  成功時に返されます。
    \param bio  FDを設定するためのWOLFSSL_BIO構造。
    \param fd  使用するファイル記述子。
    \param closeF fdをクローズする際のふるまいを指定するフラグ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int fd;
    // setup bio
    wolfSSL_BIO_set_fd(bio, fd, BIO_NOCLOSE);
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int flag);

/*!
    \ingroup IO
    \brief  BIOが解放されたときにI/Oストリームを閉じる必要があることを示すために使用されるクローズフラグを設定します。
    \return SSL_SUCCESS(1)  成功時に返されます。
    \param bio  WOLFSSL_BIO構造体。
    \param flag I/Oストリームを閉じる必要があることを示すために使用されるクローズフラグ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // setup bio
    wolfSSL_BIO_set_close(bio, BIO_NOCLOSE);
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_set_close(WOLFSSL_BIO *b, long flag);

/*!
    \ingroup IO
    \brief  この関数はBIO_SOCKETタイプのWOLFSSL_BIO_METHODを取得するために使用されます。
    \return WOLFSSL_BIO_METHOD  ソケットタイプであるWOLFSSL_BIO_METHOD構造体へのポインタ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket);
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void);

/*!
    \ingroup IO
    \brief  この関数は、WOLFSSL_BIOのライトバッファのサイズを設定するために使用されます。
    書き込みバッファが以前に設定されている場合、この関数はサイズをリセットするときに解放されます。
    読み書きインデックスを0にリセットするという点で、wolfSSL_BIO_resetに似ています。
    \return SSL_SUCCESS  書き込みバッファの設定に成功しました。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \param bio  FDを設定するためのWOLFSSL_BIO構造。
    \param size バッファサイズ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret = wolfSSL_BIO_set_write_buf_size(bio, 15000);
    // check return value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size);

/*!
    \ingroup IO
    \brief  これは2つのBIOSを一緒にペアリングするために使用されます。一対のBIOSは、2つの方法パイプと同様に、他方で読み取られることができ、その逆も同様である。BIOSの両方が同じスレッド内にあることが予想されます。この機能はスレッドセーフではありません。2つのBIOSのうちの1つを解放すると、両方ともペアになっています。書き込みバッファサイズが以前に設定されていない場合、それはペアになる前に17000（wolfssl_bio_size）のデフォルトサイズに設定されます。
    \return SSL_SUCCESS  2つのBIOSをうまくペアリングします。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \param b1  ペアを設定するための第一のWOLFSSL_BIO構造体へのポインタ。
    \param b2 第二ののWOLFSSL_BIO構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BIO* bio2;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    ret = wolfSSL_BIO_make_bio_pair(bio, bio2);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2);

/*!
    \ingroup IO
    \brief  この関数は、読み取り要求フラグを0に戻すために使用されます。
    \return SSL_SUCCESS  値を正常に設定します。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \param bio WOLFSSL_BIO構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    ...
    ret = wolfSSL_BIO_ctrl_reset_read_request(bio);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new, wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_new, wolfSSL_BIO_free
*/
int  wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO * bio);

/*!
    \ingroup IO
    \bri f  この関数は、読み取り用のバッファポインタを取得するために使用されます。
    wolfSSL_BIO_nreadとは異なり、内部読み取りインデックスは関数呼び出しから返されたサイズ分進みません。
    返される値を超えて読み取ると、アレイの境界から読み出される可能性があります。
    \return >=0  成功すると、読み取るバイト数を返します
    \param bio  WOLFSSL_BIO構造体へのポインタ。
    \param buf 読み取り用バッファへのポインタのポインタ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nread0(bio, &bufPt); // read as many bytes as possible
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite0
*/
int  wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf);

/*!
    \ingroup IO
    \biieれは、この関数は、読み取り用のバッファポインタを取得するために使用されます。
    内部読み取りインデックスは、読み取り元のバッファの先頭に指されているBUFを使用して、関数呼び出しから返されるサイズ分進みます。
    数numで要求された値よりもバイトが少ない場合、より少ない値が返されます。
    返される値を超えて読み取ると、アレイの境界から読み出される可能性があります。
    \return >=0  成功すると、読み取るバイト数を返します
    \return WOLFSSL_BIO_ERROR(-1)  Return -1を読むものではないエラーケースについて
    \param bio  WOLFSSL_BIO構造体へのポインタ。
    \param buf  読み取り配列の先頭に設定するポインタ。
    \param num 読み取りサイズ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;

    // set up bio
    ret = wolfSSL_BIO_nread(bio, &bufPt, 10); // try to read 10 bytes
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite
*/
int  wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO
    \brief  関数によって返される数のバイトを書き込むためにバッファーへのポインタを取得します。
    返されるポインタに追加のバイトを書き込んだ場合、返された値は範囲外の書き込みにつながる可能性があります。
    \return int  返されたバッファポインタに書き込むことができるバイト数を返します。
    \return WOLFSSL_BIO_UNSET(-2)  バイオペアの一部ではない場合
    \return WOLFSSL_BIO_ERROR(-1)  に書くべき部屋がこれ以上ない場合
    \param bio  WOLFSSL_BIO構造に書き込む構造。
    \param buf  書き込むためのバッファへのポインタ。
    \param num 書き込みたいサイズ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nwrite(bio, &bufPt, 10); // try to write 10 bytes
    // handle negative ret check
    // write ret bytes to bufPt
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_nread
*/
int  wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO
    \brief  バイオを初期状態にリセットします。タイプBIO_BIOの例として、これは読み書きインデックスをリセットします。
    \return 0  バイオのリセットに成功しました。
    \return WOLFSSL_BIO_ERROR(-1)  不良入力または失敗したリセットで返されます。
    \param bio WOLFSSL_BIO構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // setup bio
    wolfSSL_BIO_reset(bio);
    //use pt
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_reset(WOLFSSL_BIO *bio);

/*!
    \ingroup IO
    \brief  この関数は、指定されたオフセットへファイルポインタを調整します。これはファイルの先頭からのオフセットです。
    \return 0  正常に探しています。
    \return -1  エラーケースに遭遇した場合
    \param bio  設定するWOLFSSL_BIO構造体へのポインタ。
    \param ofs ファイルの先頭からのオフセット

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, &fp);
    // check ret value
    ret  = wolfSSL_BIO_seek(bio, 3);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs);

/*!
    \ingroup IO
    \brief  これはファイルに設定および書き込むために使用されます。現在ファイル内のデータを上書きし、BIOが解放されたときにファイルを閉じるように設定されます。
    \return SSL_SUCCESS  ファイルの開きと設定に成功しました。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \param bio  ファイルを設定するWOLFSSL_BIO構造体体。
    \param name 書き込み先ファイル名へのポインタ

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_write_filename(bio, “test.txt”);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_file
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name);

/*!
    \ingroup IO
    \brief  これはファイル値の終わりを設定するために使用されます。一般的な値は予想される正の値と混同されないように-1です。
    \return 0  完了に戻りました
    \param bio  ファイル値の終わりを設定するためのWOLFSSL_BIO構造体体。
    \param v bioにセットする値。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_set_mem_eof_return(bio, -1);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v);

/*!
    \ingroup IO
    \brief  これはWolfSSL_BIOメモリポインタのゲッター関数です。
    \return SSL_SUCCESS  ポインタSSL_SUCCESSを返す正常に（現在1の値）。
    \return SSL_FAILURE  null引数が渡された場合（現在0の値）に渡された場合に返されます。
    \param bio  メモリポインタを取得するためのWOLFSSL_BIO構造体へのポインタ。
    \param ptr WOLFSSL_BUF_MEM構造体へのポインタ（現在はchar*となっている）

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BUF_MEM* pt;
    // setup bio
    wolfSSL_BIO_get_mem_ptr(bio, &pt);
    //use pt
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **m);

/*!
    \ingroup CertsKeys
    \brief  この関数はX509の名前をバッファにコピーします。
    \return A  WOLFSSL_X509_NAME構造名メンバーのデータが正常に実行された場合、nameメンバーのデータが返されます。
    \param name  wolfssl_x509構造へのポインタ。
    \param in  WOLFSSL_X509_NAME構造体からコピーされた名前を保持するためのバッファ。
    \param sz バッファの最大サイズ

    _Example_
    \code
    WOLFSSL_X509 x509;
    char* name;
    ...
    name = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(name <= 0){
    	// There’s nothing in the buffer.
    }
    \endcode
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
char*       wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME* name, char* in, int sz);

/*!
    \ingroup CertsKeys
    \brief  この関数は証明書発行者の名前を返します。
    \return point  WOLFSSL_X509構造体の発行者メンバーへのポインタが返されます。
    \return NULL  渡された証明書がNULLの場合
    \param cert WOLFSSL_X509構造体へのポインタ

    _Example_
    \code
    WOLFSSL_X509* x509;
    WOLFSSL_X509_NAME issuer;
    ...
    issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(!issuer){
    	// NULL was returned
    } else {
    	// issuer hods the name of the certificate issuer.
    }
    \endcode
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_NAME_oneline
*/
WOLFSSL_X509_NAME*  wolfSSL_X509_get_issuer_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys
    \brief  この関数は、wolfssl_x509構造の件名メンバーを返します。
    \return pointer  wolfssl_x509_name構造へのポインタ。WOLFSSL_X509構造体がNULLの場合、または構造体の件名メンバーがNULLの場合、ポインタはNULLになることがあります。
    \param cert WOLFSSL_X509構造体へのポインタ

    _Example_
    \code
    WOLFSSL_X509* cert;
    WOLFSSL_X509_NAME name;
    …
    name = wolfSSL_X509_get_subject_name(cert);
    if(name == NULL){
	    // Deal with the NULL cacse
    }
    \endcode
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_X509_NAME*  wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys
    \brief  WOLFSSL_X509構造体のisCaメンバーをチェックして値を返します。
    \return isCA  WOLFSSL_X509構造体のisCaメンバーの値を返します。
    \return 0  有効なWOLFSSL_X509構造体が渡されない場合に返されます。
    \param cert WOLFSSL_X509構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_X509_get_isCA(ssl)){
    	// This is the CA
    }else {
    	// Failure case
    }
    \endcode
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
*/
int  wolfSSL_X509_get_isCA(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys
    \brief  この関数は、渡されたNID値に関連するテキストを取得します。
    \return int  テキストバッファのサイズを返します。
    \param name  wolfssl_x509_nameテキストを検索する。
    \param nid  検索するNID。
    \param buf  見つかったときにテキストを保持するためのバッファー。
    \param len バッファのサイズ

    _Example_
    \code
    WOLFSSL_X509_NAME* name;
    char buffer[100];
    int bufferSz;
    int ret;
    // get WOLFSSL_X509_NAME
    ret = wolfSSL_X509_NAME_get_text_by_NID(name, NID_commonName,
    buffer, bufferSz);

    //check ret value
    \endcode
    \sa none
*/
int wolfSSL_X509_NAME_get_text_by_NID(WOLFSSL_X509_NAME* name, int nid,
                                      char* buf, int len);

/*!
    \ingroup CertsKeys
    \brief  この関数は、WOLFSSL_X509構造体のsigOIDメンバーに格納されている値を返します。
    \return 0  WOLFSSL_X509構造体がNULLの場合に返されます。
    \return int  x509オブジェクトから取得された整数値が返されます。
    \param cert WOLFSSL_X509構造体へのポインタ

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509SigType = wolfSSL_X509_get_signature_type(x509);

    if(x509SigType != EXPECTED){
	// Deal with an unexpected value
    }
    \endcode
    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_notAfter
    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_get_signature_type(WOLFSSL_X509* cert);

/*!
    \brief この関数はWOLFSSL_X509構造体を解放します。
    \return なし
    \param x509 WOLFSSL_X509構造体へのポインタ

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;

    wolfSSL_X509_free(x509);

    \endcode
    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_notAfter
*/
void wolfSSL_X509_free(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief  x509署名を取得し、それをバッファに保存します。
    \return SSL_SUCCESS  関数が正常に実行された場合に返されます。署名がバッファにロードされます。
    \return SSL_FATAL_ERRROR  X509構造体またはBUFSZメンバーがNULLの場合に返します。SIG構造の長さメンバのチェックもある（SIGはX509のメンバーである）。
    \param x509  wolfssl_x509構造へのポインタ。
    \param buf  バッファへの文字ポインタ。
    \param bufSz バッファサイズを格納するint型変数へのポインタ

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    unsigned char* buf; // Initialize
    int* bufSz = sizeof(buf)/sizeof(unsigned char);
    ...
    if(wolfSSL_X509_get_signature(x509, buf, bufSz) != SSL_SUCCESS){
	    // The function did not execute successfully.
    } else{
	    // The buffer was written to correctly.
    }
    \endcode
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_get_signature_type
    \sa wolfSSL_X509_get_device_type
*/
int wolfSSL_X509_get_signature(WOLFSSL_X509* x509, unsigned char* buf, int* bufSz);

/*!
    \ingroup CertsKeys
    \brief  この関数は、WOLFSSL_X509_STRE構造体に証明書を追加します。
    \return SSL_SUCCESS  証明書が正常に追加された場合。
    \return SSL_FATAL_ERROR:  証明書が正常に追加されない場合
    \param str  証明書を追加する証明書ストア。
    \param x509 追加するWOLFSSL_X509構造体へのポインタ

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    WOLFSSL_X509* x509;
    int ret;
    ret = wolfSSL_X509_STORE_add_cert(str, x509);
    //check ret value
    \endcode
    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_STORE_add_cert(WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief  この関数は、WOLFSSL_X509_STORE_CTX構造体のチェーン変数のgetter関数です。現在チェーンは取り込まれていません。
    \return pointer  成功した場合WOLFSSL_STACK（STACK_OF(WOLFSSL_X509)）ポインタと同じ
    \return Null  失敗した場合に返されます。
    \param ctx WOLFSSL_X509_STORE_CTX構造体へのポインタ

    _Example_
    \code
    WOLFSSL_STACK* sk;
    WOLFSSL_X509_STORE_CTX* ctx;
    sk = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode
    \sa wolfSSL_sk_X509_free
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief  この関数は、渡されたWOLFSSL_X509_STORE構造体の動作を変更するためのフラグを取ります。使用されるフラグの例はWOLFSSL_CRL_CHECKです。
    \return SSL_SUCCESS  フラグを設定するときにエラーが発生しなかった場合。
    \return <0  障害の際に負の値が返されます。
    \param str  フラグを設定する証明書ストア。
    \param flag フラグ

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    int ret;
    // create and set up str
    ret = wolfSSL_X509_STORE_set_flags(str, WOLFSSL_CRL_CHECKALL);
    If (ret != SSL_SUCCESS) {
    	//check ret value and handle error case
    }
    \endcode
    \sa wolfSSL_X509_STORE_new
    \sa wolfSSL_X509_STORE_free
*/
int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store,
                                                            unsigned long flag);

/*!
    \ingroup CertsKeys
    \brief  この関数はBYTEアレイとして符号化された"not before"要素を返します。
    \return NULL  WOLFSSL_X509構造体がNULLの場合に返されます。
    \return byte  NetBeforEdataを含むバッファへのポインタが返されます。
    \param x509 WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    byte* notBeforeData = wolfSSL_X509_notBefore(x509);


    \endcode
    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notAfter
    \sa wolfSSL_X509_free
*/
const byte* wolfSSL_X509_notBefore(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief  この関数は、BYTE配列として符号化された"not after"要素を返します。
    \return NULL  WOLFSSL_X509構造体がNULLの場合に返されます。
    \return byte  notAfterDataを含むバッファへのポインタが返されます。
    \param x509 WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    byte* notAfterData = wolfSSL_X509_notAfter(x509);


    \endcode
    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_free
*/
const byte* wolfSSL_X509_notAfter(WOLFSSL_X509* x509);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSL_ASN1_INTEGER値をWOLFSSL_BIGNUM構造体にコピーするために使用されます。
    \return pointer  WOLFSSL_ASN1_INTEGER値を正常にコピーすると、WOLFSSL_BIGNUMポインタが返されます。
    \return Null  失敗時に返されます。
    \param ai WOLFSSL_ASN1_INTEGER構造体へのポインタ
    \param bn もし、既存のWOLFSSL_BIGNUM構造体にコピーしたい場合そのポインタをこの引数で指定します。
    NULLを指定すると新たにWOLFSSL_BIGNUM構造体が生成されて使用されます。


    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* ai;
    WOLFSSL_BIGNUM* bn;
    // create ai
    bn = wolfSSL_ASN1_INTEGER_to_BN(ai, NULL);

    // or if having already created bn and wanting to reuse structure
    // wolfSSL_ASN1_INTEGER_to_BN(ai, bn);
    // check bn is or return value is not NULL
    \endcode
    \sa none
*/
WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
                                       WOLFSSL_BIGNUM *bn);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSL_CTX構造で構築されている内部チェーンに証明書を追加します。
    \return SSL_SUCCESS  証明書の追加に成功したら。
    \return SSL_FAILURE  チェーンに証明書を追加することが失敗した場合。
    \param ctx  証明書を追加するためのWOLFSSL_CTX構造。
    \param x509 WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL_X509* x509;
    int ret;
    // create ctx
    ret = wolfSSL_CTX_add_extra_chain_cert(ctx, x509);
    // check ret value
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSL_CTX構造からGet Read Hapeフラグを返します。
    \return flag  成功すると、読み取り先のフラグを返します。
    \return SSL_FAILURE  ctxがnullの場合、ssl_failureが返されます。
    \param ctx WOLFSSL_CTX構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    // setup ctx
    flag = wolfSSL_CTX_get_read_ahead(ctx);
    //check flag
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_read_ahead
*/
int  wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSL_CTX構造内の読み出し先のフラグを設定します。
    \return SSL_SUCCESS  ctxが先読みフラグを設定した場合。
    \return SSL_FAILURE  ctxがNULLの場合に返されます。
    \param ctx WOLFSSL_CTX構造体へのポインタ
    \param v 先読みフラグ

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_read_ahead(ctx, flag);
    // check return value
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_get_read_ahead
*/
int  wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX* ctx, int v);

/*!
    \ingroup Setup
    \brief  この関数はOCSPで使用するオプション引数を設定します。
    \return SSL_FAILURE  CTXまたはITのCERT ManagerがNULLの場合。
    \return SSL_SUCCESS  正常に設定されている場合。
    \param ctx  WOLFSSL_CTX構造へのポインタ
    \param arg ユーザー引数

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_status_arg(ctx, data);

    //check ret value
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup Setup
    \brief  この関数は、PRFコールバックに渡すオプションの引数を設定します。
    \return SSL_FAILURE  CTXがNULLの場合
    \return SSL_SUCCESS  正常に設定されている場合。
    \param ctx  WOLFSSL_CTX構造へのポインタ
    \param arg ユーザー引数

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_opaques_prf_input_callback_arg(ctx, data);
    //check ret value
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(
        WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup Setup
    \brief  この関数は、SSLのオプションマスクを設定します。
    いくつかの有効なオプションは、ssl_op_all、ssl_op_cookie_exchange、ssl_op_no_sslv2、ssl_op_no_sslv3、ssl_op_no_tlsv1_1、ssl_op_no_tlsv1_2、ssl_op_no_compressionです。
    \return val  SSLに格納されている更新されたオプションマスク値を返します。
    \param s  オプションマスクを設定するためのWolfSSL構造。
    \param op オプションマスク。以下の値が指定可能です：<br>
    SSL_OP_ALL<br>
    SSL_OP_COOKIE_EXCHANGE<br>
    SSL_OP_NO_SSLv2<br>
    SSL_OP_NO_SSLv3<br>
    SSL_OP_NO_TLSv1<br>
    SSL_OP_NO_TLSv1_1<br>
    SSL_OP_NO_TLSv1_2<br>
    SSL_OP_NO_COMPRESSION<br>

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask = SSL_OP_NO_TLSv1
    mask  = wolfSSL_set_options(ssl, mask);
    // check mask
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_get_options
*/
long wolfSSL_set_options(WOLFSSL *s, long op);

/*!
    \ingroup Setup
    \brief  この関数は現在のオプションマスクを返します。
    \return val  SSLに格納されているマスク値を返します。
    \param ssl WOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask  = wolfSSL_get_options(ssl);
    // check mask
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_set_options
*/
long wolfSSL_get_options(const WOLFSSL *ssl);

/*!
    \ingroup Setup
    \brief  この関数は、渡されたデバッグ引数を設定するために使用されます。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  NULL SSLが渡された場合。
    \param ssl  引数を設定するためのWolfSSL構造。
    \param arg デバッグ引数

    _Example_
    \code
    WOLFSSL* ssl;
    void* args;
    int ret;
    // create ssl object
    ret  = wolfSSL_set_tlsext_debug_arg(ssl, args);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_set_tlsext_debug_arg(WOLFSSL *ssl, void *arg);

/*!
    \ingroup openSSL
    \brief  この関数は、サーバがOCSPステータス応答（OCSPステイプルとも呼ばれる）を送受信するクライアントアプリケーションが要求されたときに呼び出されます。
    \return 1  成功時に返されます。
    \return 0  エラー時に返されます。
    \param s  ssl_new()関数によって作成されたWOLFSSL構造体へのポインタ
    \param type ssl拡張タイプ。TLSEXT_STATUSTYPE_ocspのみ指定可。

    _Example_
    \code
    WOLFSSL *ssl;
    WOLFSSL_CTX *ctx;
    int ret;
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    ssl = wolfSSL_new(ctx);
    ret = WolfSSL_set_tlsext_status_type(ssl,TLSEXT_STATUSTYPE_ocsp);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type);

/*!
    \ingroup Setup
    \bri f  この関数は、れは、ピアの証明書を確認しようとした後に結果を取得するために使用されます。
    \return X509_V_OK  成功した検証について
    \return SSL_FAILURE  NULL SSLが渡された場合。
    \param ssl WOLFSSL 構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl;
    long ret;
    // attempt/complete handshake
    ret  = wolfSSL_get_verify_result(ssl);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_get_verify_result(const WOLFSSL *ssl);

/*!
    \ingroup Debug
    \brief  この関数は、wolfSSL_get_error()によって返されたエラーコードをより多くの人間が読めるエラー文字列に変換し、その文字列を出力ファイルに印刷します。ERRは、WOLFSSL_GET_ERROR()によって返され、FPがエラー文字列が配置されるファイルであるエラーコードです。
    \return なし
    \param fp  に書き込まれる人間が読めるエラー文字列の出力ファイル。
    \param err wolfSSL_get_error()で返されるエラーコード。

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    FILE* fp = ...
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_print_errors_fp(fp, err);
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_print_errors_fp(XFILE fp, int err);

/*!
    \ingroup Debug
    \brief  この関数は提供されたコールバックを使用してエラー報告を処理します。コールバック関数はエラー回線ごとに実行されます。文字列、長さ、およびuserdataはコールバックパラメータに渡されます。
    \return なし
    \param cb  コールバック関数
    \param u コールバック関数に渡されるuserdata

    _Example_
    \code
    int error_cb(const char *str, size_t len, void *u)
    { fprintf((FILE*)u, "%-*.*s\n", (int)len, (int)len, str); return 0; }
    ...
    FILE* fp = ...
    wolfSSL_ERR_print_errors_cb(error_cb, fp);
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_print_errors_cb (
        int (*cb)(const char *str, size_t len, void *u), void *u);

/*!
    \brief  この関数はWOLFSSL_CTX構造のclient_psk_cbメンバーをセットします。
    \return なし
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param cb wc_psk_client_callback はコールバック関数ポインタでWOLFSSL_CTX構造体に格納されます。
    戻り値は成功時には鍵長を返し、エラー時には０を返します。
    unsigned int (*wc_psk_client_callback)
    PSK クライアントコールバック関数の引数：<br>
    WOLFSSL* ssl - WOLFSSL構造体へのポインタ<br>
    const char* hint - ユーザーに対して表示されるヒント文字列<br>
    char* identity - ID<br>
    unsigned int id_max_len - IDバッファのサイズ<br>
    unsigned char* key - 格納される鍵<br>
    unsigned int key_max_len - 鍵の最大サイズ<br>

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    …
    static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    Unsigned int key_max_len){
    …
    wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
    \endcode
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx,
                                                    wc_psk_client_callback cb);

/*!
    \brief
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl;
    static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    Unsigned int key_max_len){
    …
    if(ssl){
    wolfSSL_set_psk_client_callback(ssl, my_psk_client_cb);
    } else {
    	// could not set callback
    }
    \endcode
    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_set_psk_server_callback
*/
void wolfSSL_set_psk_client_callback(WOLFSSL* ssl,
                                                    wc_psk_client_callback);

/*!
    \ingroup CertsKeys
    \brief  この関数はPSKアイデンティティヒントを返します。
    \return pointer  WolfSSL構造の配列メンバーに格納されている値へのconst charポインタが返されます。
    \return NULL  WOLFSSLまたは配列構造がNULLの場合に返されます。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* idHint;
    ...
    idHint = wolfSSL_get_psk_identity_hint(ssl);
    if(idHint){
    	// The hint was retrieved
    	return idHint;
    } else {
    	// Hint wasn’t successfully retrieved
    }
    \endcode
    \sa wolfSSL_get_psk_identity
*/
const char* wolfSSL_get_psk_identity_hint(const WOLFSSL*);

/*!
    \ingroup CertsKeys
    \brief  関数は、配列構造のClient_Identityメンバーへの定数ポインタを返します。
    \return string  配列構造のclient_identityメンバの文字列値。
    \return NULL  WOLFSSL構造がNULLの場合、またはWOLFSSL構造の配列メンバーがNULLの場合。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* pskID;
    ...
    pskID = wolfSSL_get_psk_identity(ssl);

    if(pskID == NULL){
	    // There is not a value in pskID
    }
    \endcode
    \sa wolfSSL_get_psk_identity_hint
    \sa wolfSSL_use_psk_identity_hint
*/
const char* wolfSSL_get_psk_identity(const WOLFSSL*);

/*!
    \ingroup CertsKeys
    \brief  この関数は、WOLFSSL_CTX構造体のserver_hintメンバーにHINT引数を格納します。
    \return SSL_SUCCESS  機能の実行が成功したために返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    const char* hint;
    int ret;
    …
    ret = wolfSSL_CTX_use_psk_identity_hint(ctx, hint);
    if(ret == SSL_SUCCESS){
    	// Function was successful.
	return ret;
    } else {
    	// Failure case.
    }
    \endcode
    \sa wolfSSL_use_psk_identity_hint
*/
int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint);

/*!
    \ingroup CertsKeys
    \brief  この関数は、wolfssl構造内の配列構造のserver_hintメンバーにHINT引数を格納します。
    \return SSL_SUCCESS  ヒントがWolfSSL構造に正常に保存された場合に返されます。
    \return SSL_FAILURE  WOLFSSLまたは配列構造がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* hint;
    ...
    if(wolfSSL_use_psk_identity_hint(ssl, hint) != SSL_SUCCESS){
    	// Handle failure case.
    }
    \endcode
    \sa wolfSSL_CTX_use_psk_identity_hint
*/
int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint);

/*!
    \brief  WOLFSSL_CTX構造体
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // Function body.
    }
    …
    if(ctx != NULL){
        wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    } else {
    	// The CTX object was not properly initialized.
    }
    \endcode
    \sa wc_psk_server_callback
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx,
                                                    wc_psk_server_callback cb);

/*!
    \brief  WolfSSL構造オプションメンバー。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // Function body.
    }
    …
    if(ssl != NULL && cb != NULL){
        wolfSSL_set_psk_server_callback(ssl, my_psk_server_cb);
    }
    \endcode
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_get_psk_identity_hint
    \sa wc_psk_server_callback
    \sa InitSuites
*/
void wolfSSL_set_psk_server_callback(WOLFSSL* ssl,
                                                    wc_psk_server_callback cb);


/*!
    \brief
    \return WOLFSSL_SUCCESS  またはwolfssl_failure.
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造体へのポインタ

    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_set_psk_callback_ctx(WOLFSSL* ssl, void* psk_ctx);

/*!
    \brief
    \return WOLFSSL_SUCCESS  またはwolfssl_failure.
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_CTX_set_psk_callback_ctx(WOLFSSL_CTX* ctx, void* psk_ctx);

/*!
    \brief
    \return void  ユーザーPSKコンテキストへのポインタ
    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl);

/*!
    \brief
    \return void  ユーザーPSKコンテキストへのポインタ
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
*/
void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief  この機能により、CTX構造のHAVAnonメンバーがコンパイル中に定義されている場合は、CTX構造のHABANONメンバーを有効にします。
    \return SSL_SUCCESS  機能が正常に実行され、CTXのHaveannonメンバーが1に設定されている場合に返されます。
    \return SSL_FAILURE  CTX構造がNULLの場合に返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    #ifdef HAVE_ANON
	if(cipherList == NULL){
	    wolfSSL_CTX_allow_anon_cipher(ctx);
	    if(wolfSSL_CTX_set_cipher_list(ctx, “ADH_AES128_SHA”) != SSL_SUCCESS){
		    // failure case
	    }
    }
    #endif
    \endcode
    \sa none
*/
int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX*);

/*!
    \ingroup Setup
    \brief  wolfsslv23_server_method()関数は、アプリケーションがサーバーであることを示すために使用され、SSL 3.0  -  TLS 1.3からプロトコルバージョンと接続するクライアントをサポートします。この関数は、wolfSSL_CTX_new()を使用してSSL / TLSコンテキストを作成するときに使用される新しいWolfssl_method構造体のメモリを割り当てて初期化します。
    \return pointer  成功した場合、呼び出しは新しく作成されたwolfssl_method構造へのポインタを返します。
    \return Failure  xmallocを呼び出すときにメモリ割り当てが失敗した場合、基礎となるMalloc()実装の失敗値が返されます（通常はerrnoがenomeemに設定されます）。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv23_server_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv23_server_method(void);

/*!
    \ingroup Setup
    \bri f  この関数は、れは、WolfSSL構造体の内部エラー状態を取得するために使用されます。
    \return wolfssl_error  SSLエラー状態、通常はマイナスを返します
    \return BAD_FUNC_ARG  sslがNULLの場合

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create ssl object
    ret  = wolfSSL_state(ssl);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int  wolfSSL_state(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief  この関数はピアの証明書を取得します。
    \return pointer  WOLFSSL_X509構造のPECRERTメンバーへのポインタが存在する場合は。
    \return 0  ピア証明書発行者サイズが定義されていない場合に返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    WOLFSSL_X509* peerCert = wolfSSL_get_peer_certificate(ssl);

    if(peerCert){
    	// You have a pointer peerCert to the peer certification
    }
    \endcode
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);

/*!
    \ingroup Debug
    \brief  この関数は、wolfSSL_get_error()を呼び出してssl_error_want_readを取得するのと似ています。基礎となるエラー状態がSSL_ERROR_WANT_READの場合、この関数は1を返しますが、それ以外の場合は0です。
    \return 1  WOLFSSL_GET_ERROR()はSSL_ERROR_WANT_READを返し、基礎となるI / Oには読み取り可能なデータがあります。
    \return 0  SSL_ERROR_WANT_READエラー状態はありません。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_want_read(ssl);
    if (ret == 1) {
    	// underlying I/O has data available for reading (SSL_ERROR_WANT_READ)
    }
    \endcode
    \sa wolfSSL_want_write
    \sa wolfSSL_get_error
*/
int wolfSSL_want_read(WOLFSSL*);

/*!
    \ingroup Debug
    \brief  この関数は、wolfSSL_get_error()を呼び出し、RETURSのSSL_ERROR_WANT_WRITEを取得するのと同じです。基礎となるエラー状態がSSL_ERROR_WANT_WRITEの場合、この関数は1を返しますが、それ以外の場合は0です。
    \return 1  WOLFSSL_GET_ERROR()はSSL_ERROR_WANT_WRITEを返します。基礎となるI / Oは、基礎となるSSL接続で進行状況を行うために書き込まれるデータを必要とします。
    \return 0  ssl_error_want_writeエラー状態はありません。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_want_write(ssl);
    if (ret == 1) {
    	// underlying I/O needs data to be written (SSL_ERROR_WANT_WRITE)
    }
    \endcode
    \sa wolfSSL_want_read
    \sa wolfSSL_get_error
*/
int wolfSSL_want_write(WOLFSSL*);

/*!
    \ingroup Setup
    \brief  wolfsslデフォルトでは、有効な日付範囲と検証済みの署名のためにピア証明書をチェックします。wolfssl_connect()またはwolfssl_accept()の前にこの関数を呼び出すと、実行するチェックのリストにドメイン名チェックが追加されます。DN受信時にピア証明書を確認するためのドメイン名を保持します。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  メモリエラーが発生した場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造体へのポインタ

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    char* domain = (char*) “www.yassl.com”;
    ...

    ret = wolfSSL_check_domain_name(ssl, domain);
    if (ret != SSL_SUCCESS) {
       // failed to enable domain name check
    }
    \endcode
    \sa none
*/
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn);

/*!
    \ingroup TLS
    \brief  使用するためにWolfSSLライブラリを初期化します。アプリケーションごとに1回、その他のライブラリへの呼び出しの前に呼び出す必要があります。
    \return SSL_SUCCESS  成功した場合に返されます。、通話が戻ります。
    \return BAD_MUTEX_E  返される可能性があるエラーです。

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL library
    }

    \endcode
    \sa wolfSSL_Cleanup
*/
int wolfSSL_Init(void);

/*!
    \ingroup TLS
    \brief  さらなる使用からWOLFSSLライブラリを初期化します。ライブラリによって使用されるリソースを解放しますが、呼び出される必要はありません。
    \return SSL_SUCCESS  エラーを返しません。

    _Example_
    \code
    wolfSSL_Cleanup();
    \endcode
    \sa wolfSSL_Init
*/
int wolfSSL_Cleanup(void);

/*!
    \ingroup IO
    \brief  この関数は現在のライブラリーバージョンを返します。
    \return LIBWOLFSSL_VERSION_STRING  バージョンを定義するconst charポインタ。

    _Example_
    \code
    char version[MAXSIZE];
    version = wolfSSL_KeepArrays();
    …
    if(version != ExpectedVersion){
	    // Handle the mismatch case
    }
    \endcode
    \sa word32_wolfSSL_lib_version_hex
*/
const char* wolfSSL_lib_version(void);

/*!
    \ingroup IO
    \brief  この関数は、現在のライブラリーのバージョンを16進表記で返します。
    \return LILBWOLFSSL_VERSION_HEX  wolfssl / version.hで定義されている16進数バージョンを返します。

    _Example_
    \code
    word32 libV;
    libV = wolfSSL_lib_version_hex();

    if(libV != EXPECTED_HEX){
	    // How to handle an unexpected value
    } else {
	    // The expected result for libV
    }
    \endcode
    \sa wolfSSL_lib_version
*/
word32 wolfSSL_lib_version_hex(void);

/*!
    \ingroup IO
    \brief  SSLメソッドの側面に基づいて、実際の接続または承認を実行します。クライアント側から呼び出された場合、サーバ側から呼び出された場合にwolfssl_accept()が実行されている間にwolfssl_connect()が行われる。
    \return SSL_SUCCESS  成功した場合に返されます。に返却されます。（注意、古いバージョンは0を返します）
    \return SSL_FATAL_ERROR  基礎となる呼び出しがエラーになった場合に返されます。特定のエラーコードを取得するには、wolfSSL_get_error()を使用してください。

    _Example_
    \code
    int ret = SSL_FATAL_ERROR;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_negotiate(ssl);
    if (ret == SSL_FATAL_ERROR) {
    	// SSL establishment failed
	int error_code = wolfSSL_get_error(ssl);
	...
    }
    ...
    \endcode
    \sa SSL_connect
    \sa SSL_accept
*/
int wolfSSL_negotiate(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  SSL接続に圧縮を使用する機能をオンにします。両側には圧縮がオンになっている必要があります。そうでなければ圧縮は使用されません。ZLIBライブラリは実際のデータ圧縮を実行します。ライブラリにコンパイルするには、システムの設定システムに--with-libzを使用し、そうでない場合はhand_libzを定義します。送受信されるメッセージの実際のサイズを減らす前にデータを圧縮している間に、圧縮によって保存されたデータの量は通常、ネットワークの遅いすべてのネットワークを除いたものよりも分析に時間がかかります。
    \return SSL_SUCCESS  成功時に返されます。
    \return NOT_COMPILED_IN  圧縮サポートがライブラリに組み込まれていない場合に返されます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_compression(ssl);
    if (ret == SSL_SUCCESS) {
    	// successfully enabled compression for SSL session
    }
    \endcode
    \sa none
*/
int wolfSSL_set_compression(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数はSSLセッションタイムアウト値を秒単位で設定します。
    \return SSL_SUCCESS  セッションを正常に設定すると返されます。
    \return BAD_FUNC_ARG  sslがNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造体へのポインタ

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_timeout(ssl, 500);
    if (ret != SSL_SUCCESS) {
    	// failed to set session timeout value
    }
    ...
    \endcode
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
int wolfSSL_set_timeout(WOLFSSL* ssl, unsigned int to);

/*!
    \ingroup Setup
    \brief  この関数は、指定されたSSLコンテキストに対して、SSLセッションのタイムアウト値を秒単位で設定します。
    \return the  wolfssl_error_code_opensslの場合、以前のタイムアウト値
    \return defined  成功しています。定義されていない場合、SSL_SUCCESSは返されます。
    \return BAD_FUNC_ARG  入力コンテキスト（CTX）がNULLのときに返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    ret = wolfSSL_CTX_set_timeout(ctx, 500);
    if (ret != SSL_SUCCESS) {
	    // failed to set session timeout value
    }
    \endcode
    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_session_cache_mode
*/
int wolfSSL_CTX_set_timeout(WOLFSSL_CTX* ctx, unsigned int to);

/*!
    \ingroup openSSL
    \brief  ピアの証明書チェーンを取得します。
    \return chain  正常にコールがピアの証明書チェーンを返します。
    \return 0  無効なWolfSSLポインタが関数に渡されると返されます。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief  ピアの証明書チェーン数を取得します。
    \return Success  正常にコールがピアの証明書チェーン数を返します。
    \return 0  無効なチェーンポインタが関数に渡されると返されます。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
int  wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain);

/*!
    \ingroup openSSL
    \brief  Index（IDX）のピアのASN1.DER証明書長をバイト単位で取得します。
    \return Success  正常にコールがインデックス別にピアの証明書長をバイト単位で返します。
    \return 0  無効なチェーンポインタが関数に渡されると返されます。
    \param chain  有効なwolfssl_x509_chain構造へのポインタ。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
int  wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup openSSL
    \brief  インデックス（IDX）でピアのASN1.DER証明書を取得します。
    \return Success  正常にコールがインデックスでピアの証明書を返します。
    \return 0  無効なチェーンポインタが関数に渡されると返されます。
    \param chain  有効なwolfssl_x509_chain構造へのポインタ。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert_pem
*/
unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup CertsKeys
    \brief  この関数は、証明書のチェーンからのピアのWOLFSSL_X509構造体をインデックス（IDX）で取得します。
    \return pointer  WOLFSSL_X509構造体へのポインタを返します。
    \param chain  動的メモリsession_cacheの場合に使用されるWOLFSSL_X509_CHAINへのポインタ。

    注意：本関数から返された構造体をwolfSSL_FreeX509()を呼び出して解放するのはユーザーの責任です。

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = &session->chain;
    int idx = 999; // set idx
    ...
    WOLFSSL_X509* ptr;
    prt = wolfSSL_get_chain_X509(chain, idx);

    if(ptr != NULL){
        //ptr contains the cert at the index specified
        wolfSSL_FreeX509(ptr);
    } else {
	    // ptr is NULL
    }
    \endcode
    \sa InitDecodedCert
    \sa ParseCertRelative
    \sa CopyDecodedToX509
*/
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup openSSL
    \brief  インデックス（IDX）でピアのPEM証明書を取得します。
    \return Success  正常にコールがインデックスでピアの証明書を返します。
    \return 0  無効なチェーンポインタが関数に渡されると返されます。
    \param chain  有効なwolfssl_x509_chain構造へのポインタ。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
*/
int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx,
                                unsigned char* buf, int inLen, int* outLen);

/*!
    \ingroup openSSL
    \brief  セッションのIDを取得します。セッションIDは常に32バイトの長さです。
    \return id  セッションID。

    _Example_
    \code
    none
    \endcode
    \sa SSL_get_session
*/
const unsigned char* wolfSSL_get_sessionID(const WOLFSSL_SESSION* s);

/*!
    \ingroup openSSL
    \brief  ピアの証明書のシリアル番号を取得します。シリアル番号バッファ（IN）は少なくとも32バイト以上であり、入力として* INOUTSZ引数として提供されます。関数を呼び出した後* INOUTSZはINバッファに書き込まれた実際の長さをバイト単位で保持します。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  関数の不良引数が見つかった場合に返されます。
    \param in  シリアル番号バッファは少なくとも32バイトの長さであるべきです

    _Example_
    \code
    none
    \endcode
    \sa SSL_get_peer_certificate
*/
int  wolfSSL_X509_get_serial_number(WOLFSSL_X509* x509, unsigned char* in,
                                    int* inOutSz);

/*!
    \ingroup CertsKeys
    \brief  証明書から件名の共通名を返します。
    \return NULL  X509構造がNULLの場合に返されます
    \return string  サブジェクトの共通名の文字列表現は成功に返されます

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509Cn = wolfSSL_X509_get_subjectCN(x509);
    if(x509Cn == NULL){
	    // Deal with NULL case
    } else {
	    // x509Cn contains the common name
    }
    \endcode
    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys
    \brief  この関数は、wolfssl_x509構造体のDERエンコードされた証明書を取得します。
    \return buffer  この関数はDerbuffer構造体のバッファメンバーを返します。これはバイト型です。
    \return NULL  x509またはoutszパラメーターがnullの場合に返されます。
    \param x509  証明書情報を含むWolfSSL_X509構造へのポインタ。

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    int* outSz; // initialize
    ...
    byte* x509Der = wolfSSL_X509_get_der(x509, outSz);
    if(x509Der == NULL){
	    // Failure case one of the parameters was NULL
    }
    \endcode
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz);

/*!
    \ingroup CertsKeys
    \brief  この関数は、x509がnullのかどうかを確認し、そうでない場合は、x509構造体のノッカスメンバーを返します。
    \return pointer  ASN1_TIMEを使用してX509構造体のノカフターメンバーに構造体を表明します。
    \return NULL  X509オブジェクトがNULLの場合に返されます。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    ...
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notAfter(x509);
    if(notAfter == NULL){
        // Failure case, the x509 object is null.
    }
    \endcode
    \sa wolfSSL_X509_get_notBefore
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys
    \brief  この関数はX509証明書のバージョンを取得します。
    \return 0  X509構造がNULLの場合に返されます。
    \return version  X509構造に保存されているバージョンが返されます。

    _Example_
    \code
    WOLFSSL_X509* x509;
    int version;
    ...
    version = wolfSSL_X509_version(x509);
    if(!version){
	    // The function returned 0, failure case.
    }
    \endcode
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
int wolfSSL_X509_version(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys
    \brief  no_stdio_filesystemが定義されている場合、この関数はヒープメモリを割り当て、wolfssl_x509構造を初期化してそれにポインタを返します。
    \return *WOLFSSL_X509  関数が正常に実行された場合、WolfSSL_X509構造ポインタが返されます。
    \return NULL  Xftellマクロの呼び出しが負の値を返す場合。
    \param x509  wolfssl_x509ポインタへのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509a = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    WOLFSSL_X509** x509 = x509a;
    XFILE file;  (mapped to struct fs_file*)
    ...
    WOLFSSL_X509* newX509 = wolfSSL_X509_d2i_fp(x509, file);
    if(newX509 == NULL){
	    // The function returned NULL
    }
    \endcode
    \sa wolfSSL_X509_d2i
    \sa XFTELL
    \sa XREWIND
    \sa XFSEEK
*/
WOLFSSL_X509*
        wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, FILE* file);

/*!
    \ingroup CertsKeys
    \brief  関数はX509証明書をメモリにロードします。
    \return pointer  実行された実行は、wolfssl_x509構造へのポインタを返します。
    \return NULL  証明書が書き込まれなかった場合に返されます。
    \param fname  ロードする証明書ファイル。

    _Example_
    \code
    #define cliCert    “certs/client-cert.pem”
    …
    X509* x509;
    …
    x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM);
    AssertNotNull(x509);
    \endcode
    \sa InitDecodedCert
    \sa PemToDer
    \sa wolfSSL_get_certificate
    \sa AssertNotNull
*/
WOLFSSL_X509*
    wolfSSL_X509_load_certificate_file(const char* fname, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、デバイスの種類をX509構造からバッファにコピーします。
    \return pointer  X509構造からデバイスの種類を保持するバイトポインタを返します。
    \return NULL  バッファサイズがNULLの場合に返されます。
    \param x509  wolfssl_x509_new()で作成されたwolfssl_x509構造へのポインタ。
    \param in  デバイスタイプ（バッファ）を保持するバイトタイプへのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    byte* in;
    int* inOutSz;
    ...
    byte* deviceType = wolfSSL_X509_get_device_type(x509, in, inOutSz);

    if(!deviceType){
	    // Failure case, NULL was returned.
    }
    \endcode
    \sa wolfSSL_X509_get_hw_type
    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_d2i
*/
unsigned char*
           wolfSSL_X509_get_device_type(WOLFSSL_X509* x509, unsigned char* in,
                                        int* inOutSz);

/*!
    \ingroup CertsKeys
    \brief  この関数は、wolfssl_x509構造のHWTypeメンバーをバッファにコピーします。
    \return byte  この関数は、wolfssl_x509構造のHWTypeメンバーに以前に保持されているデータのバイトタイプを返します。
    \return NULL  inoutszがnullの場合に返されます。
    \param x509  証明書情報を含むWolfSSL_X509構造へのポインタ。
    \param in  バッファを表すバイトを入力するポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509;  // X509 certificate
    byte* in;  // initialize the buffer
    int* inOutSz;  // holds the size of the buffer
    ...
    byte* hwType = wolfSSL_X509_get_hw_type(x509, in, inOutSz);

    if(hwType == NULL){
	    // Failure case function returned NULL.
    }
    \endcode
    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_get_device_type
*/
unsigned char*
           wolfSSL_X509_get_hw_type(WOLFSSL_X509* x509, unsigned char* in,
                                    int* inOutSz);

/*!
    \ingroup CertsKeys
    \brief  この関数はX509オブジェクトのhwserialNumメンバを返します。
    \return pointer  この関数は、X509オブジェクトからロードされたシリアル番号を含むINバッファへのバイトポインタを返します。
    \param x509  証明書情報を含むWOLFSSL_X509構造へのポインタ。
    \param in  コピーされるバッファへのポインタ。

    _Example_
    \code
    char* serial;
    byte* in;
    int* inOutSz;
    WOLFSSL_X509 x509;
    ...
    serial = wolfSSL_X509_get_hw_serial_number(x509, in, inOutSz);

    if(serial == NULL || serial <= 0){
    	// Failure case
    }
    \endcode
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
unsigned char*
           wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509* x509,
                                             unsigned char* in, int* inOutSz);

/*!
    \ingroup IO
    \brief  この関数はクライアント側で呼び出され、ピアの証明書チェーンを取得するのに十分な長さだけサーバーを持つSSL / TLSハンドシェイクを開始します。この関数が呼び出されると、基礎となる通信チャネルはすでに設定されています。 wolfssl_connect_cert()は、ブロックと非ブロックI / Oの両方で動作します。基礎となるI / Oがノンブロッキングである場合、wolfsl_connect_cert()は、wolfssl_connect_cert_cert()のニーズを満たすことができなかったときに戻ります。ハンドシェイクを続けます。この場合、wolfSSL_get_error()への呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを生成します。通話プロセスは、基礎となるI / Oが準備ができて、wolfsslがオフになっているところを拾うときに、wolfssl_connect_cert()への呼び出しを繰り返す必要があります。ノンブロッキングソケットを使用する場合は、何も実行する必要がありますが、select()を使用して必要な条件を確認できます。基礎となる入出力がブロックされている場合、wolfssl_connect_cert()はピアの証明書チェーンが受信されたらのみ返されます。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FAILURE  SSLセッションパラメータがNULLの場合、返されます。
    \return SSL_FATAL_ERROR  エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出します。

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    ret = wolfSSL_connect_cert(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept
*/
int  wolfSSL_connect_cert(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief  WOLFSSL_D2I_PKCS12_BIO（D2I_PKCS12_BIO）は、WOLFSSL_BIOから構造WC_PKCS12へのPKCS12情報にコピーされます。この情報は、オプションのMAC情報を保持するための構造とともにコンテンツに関する情報のリストとして構造内に分割されています。構造体WC_PKCS12で情報がチャンク（ただし復号化されていない）に分割された後、それはその後、呼び出しによって解析および復号化され得る。
    \return WC_PKCS12  WC_PKCS12構造へのポインタ。
    \return Failure  関数に失敗した場合はNULLを返します。
    \param bio  PKCS12バッファを読み取るためのWOLFSSL_BIO構造。

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode
    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12** pkcs12);

/*!
    \ingroup openSSL
    \brief  WOLFSSL_I2D_PKCS12_BIO（I2D_PKCS12_BIO）は、構造WC_PKCS12からWOLFSSL_BIOへの証明書情報にコピーされます。
    \return 1  成功のために。
    \return Failure  0。
    \param bio  PKCS12バッファを書き込むためのWOLFSSL_BIO構造。

    _Example_
    \code
    WC_PKCS12 pkcs12;
    FILE *f;
    byte buffer[5300];
    char file[] = "./test.p12";
    int bytes;
    WOLFSSL_BIO* bio;
    pkcs12 = wc_PKCS12_new();
    f = fopen(file, "rb");
    bytes = (int)fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    //convert the DER file into an internal structure
    wc_d2i_PKCS12(buffer, bytes, pkcs12);
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    //convert PKCS12 structure into bio
    wolfSSL_i2d_PKCS12_bio(bio, pkcs12);
    wc_PKCS12_free(pkcs)
    //use bio
    \endcode
    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12* pkcs12);

/*!
    \ingroup openSSL
    \brief  pkcs12は、configureコマンドへの-enable-openSSLAXTRAを追加することで有効にできます。それは復号化のためにトリプルDESとRC4を使うことができるので、OpenSSlextra（--enable-des3 -enable-arc4）を有効にするときにもこれらの機能を有効にすることをお勧めします。 wolfsslは現在RC2をサポートしていませんので、RC2での復号化は現在利用できません。これは、.p12ファイルを作成するためにOpenSSLコマンドラインで使用されるデフォルトの暗号化方式では注目すかもしれません。 WOLFSSL_PKCS12_PARSE（PKCS12_PARSE）。この関数が最初に行っているのは、存在する場合はMacが正しいチェックです。 MACが失敗した場合、関数は返され、保存されているコンテンツ情報のいずれかを復号化しようとしません。この関数は、バッグタイプを探している各コンテンツ情報を介して解析します。バッグタイプがわかっている場合は、必要に応じて復号化され、構築されている証明書のリストに格納されているか、見つかったキーとして保存されます。すべてのバッグを介して解析した後、見つかったキーは、一致するペアが見つかるまで証明書リストと比較されます。この一致するペアはキーと証明書として返され、オプションで見つかった証明書リストはstack_of証明書として返されます。瞬間、CRL、秘密または安全なバッグがスキップされ、解析されません。デバッグプリントアウトを見ることで、これらまたは他の「不明」バッグがスキップされているかどうかがわかります。フレンドリー名などの追加の属性は、PKCS12ファイルを解析するときにスキップされます。
    \return SSL_SUCCESS  PKCS12の解析に成功しました。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \param pkcs12  wc_pkcs12解析する構造
    \param paswd  PKCS12を復号化するためのパスワード。
    \param pkey  PKCS12からデコードされた秘密鍵を保持するための構造。
    \param cert  PKCS12から復号された証明書を保持する構造

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode
    \sa wolfSSL_d2i_PKCS12_bio
    \sa wc_PKCS12_free
*/
int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
     WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert, WOLF_STACK_OF(WOLFSSL_X509)** ca);

/*!
    \ingroup CertsKeys
    \brief  サーバーDIFFIE-HELLMANエフェメラルパラメータ設定。この関数は、サーバーがDHEを使用する暗号スイートをネゴシエートしている場合に使用するグループパラメータを設定します。
    \return SSL_SUCCESS  成功時に返されます。
    \return MEMORY_ERROR  メモリエラーが発生した場合に返されます。
    \return SIDE_ERROR  この関数がSSLサーバではなくSSLクライアントで呼び出されると返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param p  Diffie-Hellman素数パラメータ。
    \param pSz  pのサイズ。
    \param g  Diffie-Hellman "Generator"パラメータ。

    _Example_
    \code
    WOLFSSL* ssl;
    static unsigned char p[] = {...};
    static unsigned char g[] = {...};
    ...
    wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
    \endcode
    \sa SSL_accept
*/
int  wolfSSL_SetTmpDH(WOLFSSL* ssl, const unsigned char* p, int pSz,
                                const unsigned char* g, int gSz);

/*!
    \ingroup CertsKeys
    \brief  関数はwolfssl_settmph_buffer_wrapperを呼び出します。これはDiffie-Hellmanパラメータのラッパーです。
    \return SSL_SUCCESS  実行に成功した場合。
    \return SSL_BAD_FILETYPE  ファイルの種類がpemではなく、asn.1ではない場合WC_DHParamSLOADが正常に戻っていない場合は、も返されます。
    \return SSL_NO_PEM_HEADER  PEMヘッダーがない場合はPemToderから返します。
    \return SSL_BAD_FILE  PemToderにファイルエラーがある場合に返されます。
    \return SSL_FATAL_ERROR  コピーエラーが発生した場合はPemToderから返されました。
    \return MEMORY_E   - メモリ割り当てエラーが発生した場合
    \return BAD_FUNC_ARG  wolfssl構造体がnullの場合、またはそうでない場合はサブルーチンに渡された場合に返されます。
    \return DH_KEY_SIZE_E  wolfssl_settmph()またはWOLFSSL_CTX_settmph()の鍵サイズエラーがある場合に返されます。
    \return SIDE_ERROR  wolfssl_settmphのサーバー側ではない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param buf  wolfssl_settmph_file_wrapperから渡された割り当てバッファー。
    \param sz  ファイルのサイズ（wolfssl_settmph_file_wrapper内のfname）を保持するロングint。

    _Example_
    \code
    Static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    long sz = 0;
    byte* myBuffer = staticBuffer[FILE_BUFFER_SIZE];
    …
    if(ssl)
    ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    \endcode
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wc_DhParamsLoad
    \sa wolfSSL_SetTmpDH
    \sa PemToDer
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int  wolfSSL_SetTmpDH_buffer(WOLFSSL* ssl, const unsigned char* b, long sz,
                                       int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、wolfssl_settmph_file_wrapperを呼び出してサーバdiffie-hellmanパラメータを設定します。
    \return SSL_SUCCESS  この機能の正常な完了とそのサブルーチンの完了に戻りました。
    \return MEMORY_E  この関数またはサブルーチンにメモリ割り当てが失敗した場合に返されます。
    \return SIDE_ERROR  WolfSSL構造体にあるオプション構造のサイドメンバーがサーバー側ではない場合。
    \return SSL_BAD_FILETYPE  証明書が一連のチェックに失敗した場合は返します。
    \return DH_KEY_SIZE_E  DHパラメーターの鍵サイズがWolfSSL構造体のMinkKeyszメンバーの値より小さい場合に返されます。
    \return DH_KEY_SIZE_E  DHパラメータの鍵サイズがwolfssl構造体のMAXDHKEYSZメンバーの値よりも大きい場合に返されます。
    \return BAD_FUNC_ARG  wolfssl構造など、引数値がnullの場合に返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param fname  証明書を保持している定数の文字ポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* dhParam;
    …
    AssertIntNE(SSL_SUCCESS,
    wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM));
    \endcode
    \sa wolfSSL_CTX_SetTmpDH_file
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
*/
int  wolfSSL_SetTmpDH_file(WOLFSSL* ssl, const char* f, int format);

/*!
    \ingroup CertsKeys
    \brief  サーバーCTX Diffie-Hellmanのパラメータを設定します。
    \return SSL_SUCCESS  関数とすべてのサブルーチンがエラーなしで戻った場合に返されます。
    \return BAD_FUNC_ARG  CTX、P、またはGパラメーターがNULLの場合に返されます。
    \return DH_KEY_SIZE_E  DHパラメータの鍵サイズがWOLFSSL_CTX構造体のMindHKEYSZメンバーの値より小さい場合に返されます。
    \return DH_KEY_SIZE_E  DHパラメータの鍵サイズがWOLFSSL_CTX構造体のMaxDhkeySZメンバーの値よりも大きい場合に返されます。
    \return MEMORY_E  この関数またはサブルーチンにメモリの割り当てが失敗した場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param p  ServerDH_P構造体のバッファメンバーにロードされた定数の符号なし文字ポインタ。
    \param pSz  pのサイズを表すint型は、max_dh_sizeに初期化されます。
    \param g  ServerDh_g構造体のバッファメンバーにロードされた定数の符号なし文字ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx =  wolfSSL_CTX_new( protocol );
    byte* p;
    byte* g;
    word32 pSz = (word32)sizeof(p)/sizeof(byte);
    word32 gSz = (word32)sizeof(g)/sizeof(byte);
    …
    int ret =  wolfSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);

    if(ret != SSL_SUCCESS){
    	// Failure case
    }
    \endcode
    \sa wolfSSL_SetTmpDH
    \sa wc_DhParamsLoad
*/
int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);

/*!
    \ingroup CertsKeys
    \brief  wolfssl_settmph_buffer_wrapperを呼び出すラッパー関数
    \return 0  実行が成功するために返されました。
    \return BAD_FUNC_ARG  CTXパラメータまたはBUFパラメータがNULLの場合に返されます。
    \return MEMORY_E  メモリ割り当てエラーがある場合
    \return SSL_BAD_FILETYPE  フォーマットが正しくない場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param buf  バッファとして割り当てられ、wolfssl_settmpdh_buffer_wrapperに渡された定数の符号なし文字型へのポインタ。
    \param sz  wolfssl_settmph_file_wrapper()のFNAMEパラメータから派生した長い整数型。

    _Example_
    \code
    static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    #ifdef WOLFSSL_SMALL_STACK
    byte staticBuffer[1]; // force heap usage
    #else
    byte* staticBuffer;
    long sz = 0;
    …
    if(ssl){
    	ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    } else {
    ret = wolfSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }
    \endcode
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTMpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int  wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX* ctx, const unsigned char* b,
                                           long sz, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、wolfssl_settmph_file_wrapperを呼び出してサーバーDiffie-Hellmanパラメータを設定します。
    \return SSL_SUCCESS  wolfssl_settmph_file_wrapperまたはそのサブルーチンのいずれかが正常に戻った場合に返されます。
    \return MEMORY_E  動的メモリの割り当てがサブルーチンで失敗した場合に返されます。
    \return BAD_FUNC_ARG  CTXまたはFNAMEパラメータがNULLまたはサブルーチンがNULL引数に渡された場合に返されます。
    \return SSL_BAD_FILE  証明書ファイルが開くことができない場合、またはファイルの一連のチェックがwolfssl_settmpdh_file_wrapperから失敗した場合に返されます。
    \return SSL_BAD_FILETYPE  フォーマットがwolfssl_settmph_buffer_wrapper()からPEMまたはASN.1ではない場合に返されます。
    \return DH_KEY_SIZE_E  DHパラメータの鍵サイズがWOLFSSL_CTX構造体のMindHKEYSZメンバーの値より小さい場合に返されます。
    \return DH_KEY_SIZE_E  DHパラメータの鍵サイズがWOLFSSL_CTX構造体のMaxDhkeySZメンバーの値よりも大きい場合に返されます。
    \return SIDE_ERROR  wolfssl_settmph()で返されたサイドがサーバー終了ではない場合。
    \return SSL_NO_PEM_HEADER  PEMヘッダーがない場合はPemToderから返されます。
    \return SSL_FATAL_ERROR  メモリコピーの失敗がある場合はPemToderから返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param fname  証明書ファイルへの定数文字ポインタ。

    _Example_
    \code
    #define dhParam     “certs/dh2048.pem”
    #DEFINE aSSERTiNTne(x, y)     AssertInt(x, y, !=, ==)
    WOLFSSL_CTX* ctx;
    …
    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()))
    …
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(NULL, dhParam,
    SSL_FILETYPE_PEM));
    \endcode
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa AllocDer
    \sa PemToDer
*/
int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* f,
                                             int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、WOLFSSL_CTX構造体のminkkeyszメンバーにアクセスして、Diffie Hellman鍵サイズの最小サイズ（ビット単位）を設定します。
    \return SSL_SUCCESS  関数が正常に完了した場合に返されます。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がnullの場合、またはキーz_BITSが16,000を超えるか、または8によって割り切れない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    public static int CTX_SetMinDhKey_Sz(IntPtr ctx, short minDhKey){
    …
    return wolfSSL_CTX_SetMinDhKey_Sz(local_ctx, minDhKeyBits);
    \endcode
    \sa wolfSSL_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetMaxDhKey_Sz
    \sa wolfSSL_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
    \sa wolfSSL_CTX_SetTMpDH_file
*/
int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX* ctx, word16);

/*!
    \ingroup CertsKeys
    \brief  WolfSSL構造のDiffie-Hellman鍵の最小サイズ（ビット単位）を設定します。
    \return SSL_SUCCESS  最小サイズは正常に設定されました。
    \return BAD_FUNC_ARG  wolfssl構造はNULL、またはKeysz_BITSが16,000を超えるか、または8によって割り切れない場合
    \param ssl  wolfssl_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz_bits;
    ...
    if(wolfSSL_SetMinDhKey_Sz(ssl, keySz_bits) != SSL_SUCCESS){
	    // Failed to set.
    }
    \endcode
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys
    \brief  この関数は、WOLFSSL_CTX構造体のmaxdhkeyszメンバーにアクセスして、Diffie Hellman鍵サイズの最大サイズ（ビット単位）を設定します。
    \return SSL_SUCCESS  関数が正常に完了した場合に返されます。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がnullの場合、またはキーz_BITSが16,000を超えるか、または8によって割り切れない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    public static int CTX_SetMaxDhKey_Sz(IntPtr ctx, short maxDhKey){
    …
    return wolfSSL_CTX_SetMaxDhKey_Sz(local_ctx, keySz_bits);
    \endcode
    \sa wolfSSL_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
    \sa wolfSSL_CTX_SetTMpDH_file
*/
int wolfSSL_CTX_SetMaxDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits);

/*!
    \ingroup CertsKeys
    \brief  WolfSSL構造のDiffie-Hellman鍵の最大サイズ（ビット単位）を設定します。
    \return SSL_SUCCESS  最大サイズは正常に設定されました。
    \return BAD_FUNC_ARG  WOLFSSL構造はNULLまたはKEYSZパラメータは許容サイズより大きかったか、または8によって割り切れませんでした。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz;
    ...
    if(wolfSSL_SetMaxDhKey(ssl, keySz) != SSL_SUCCESS){
	    // Failed to set.
    }
    \endcode
    \sa wolfSSL_CTX_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMaxDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys
    \brief  オプション構造のメンバーであるDHKEYSZ（ビット内）の値を返します。この値は、Diffie-Hellman鍵サイズをバイト単位で表します。
    \return dhKeySz  サイズを表す整数値であるssl-> options.dhkeyszで保持されている値を返します。
    \return BAD_FUNC_ARG  wolfssl構造体がNULLの場合に返します。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int dhKeySz;
    ...
    dhKeySz = wolfSSL_GetDhKey_Sz(ssl);

    if(dhKeySz == BAD_FUNC_ARG || dhKeySz <= 0){
    	// Failure case
    } else {
    	// dhKeySz holds the size of the key.
    }
    \endcode
    \sa wolfSSL_SetMinDhKey_sz
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int wolfSSL_GetDhKey_Sz(WOLFSSL*);

/*!
    \ingroup CertsKeys
    \brief  WOLFSSL_CTX構造体とwolfssl_cert_manager構造の両方で最小RSA鍵サイズを設定します。
    \return SSL_SUCCESS  機能の実行に成功したことに戻ります。
    \return BAD_FUNC_ARG  CTX構造がNULLの場合、またはKEYSZがゼロより小さいか、または8によって割り切れない場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = SSL_CTX_new(method);
    (void)minDhKeyBits;
    ourCert = myoptarg;
    …
    minDhKeyBits = atoi(myoptarg);
    …
    if(wolfSSL_CTX_SetMinRsaKey_Sz(ctx, minRsaKeyBits) != SSL_SUCCESS){
    …
    \endcode
    \sa wolfSSL_SetMinRsaKey_Sz
*/
int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX* ctx, short keySz);

/*!
    \ingroup CertsKeys
    \brief  WolfSSL構造にあるRSAのためのビットで最小許容鍵サイズを設定します。
    \return SSL_SUCCESS  最小値が正常に設定されました。
    \return BAD_FUNC_ARG  SSL構造がNULLの場合、またはKSYSZがゼロより小さい場合、または8によって割り切れない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    short keySz;
    …

    int isSet =  wolfSSL_SetMinRsaKey_Sz(ssl, keySz);
    if(isSet != SSL_SUCCESS){
	    Failed to set.
    }
    \endcode
    \sa wolfSSL_CTX_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinRsaKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys
    \brief  wolf_ctx構造体とwolfssl_cert_manager構造体のECC鍵の最小サイズをビット単位で設定します。
    \return SSL_SUCCESS  実行が成功したために返され、MineCkeyszメンバーが設定されます。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がnullの場合、または鍵が負の場合、または8によって割り切れない場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    short keySz; // minimum key size
    …
    if(wolfSSL_CTX_SetMinEccKey(ctx, keySz) != SSL_SUCCESS){
	    // Failed to set min key size
    }
    \endcode
    \sa wolfSSL_SetMinEccKey_Sz
*/
int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX* ssl, short keySz);

/*!
    \ingroup CertsKeys
    \brief  オプション構造のMineCckeyszメンバーの値を設定します。オプション構造体は、WolfSSL構造のメンバーであり、SSLパラメータを介してアクセスされます。
    \return SSL_SUCCESS  関数がオプション構造のMineCckeyszメンバーを正常に設定した場合。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がnullの場合、または鍵サイズ（keysz）が0（ゼロ）未満の場合、または8で割り切れない場合。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx); // New session
    short keySz = 999; // should be set to min key size allowable
    ...
    if(wolfSSL_SetMinEccKey_Sz(ssl, keySz) != SSL_SUCCESS){
	    // Failure case.
    }
    \endcode
    \sa wolfSSL_CTX_SetMinEccKey_Sz
    \sa wolfSSL_CTX_SetMinRsaKey_Sz
    \sa wolfSSL_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinEccKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys
    \brief  この関数は、eap_tlsとeap-ttlsによって、マスターシークレットからキーイングマテリアルを導出します。
    \return BUFFER_E  バッファの実際のサイズが許容最大サイズを超える場合に返されます。
    \return MEMORY_E  メモリ割り当てにエラーがある場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param msk  p_hash関数の結果を保持するvoidポインタ変数。
    \param len  MSK変数の長さを表す符号なし整数。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);;
    void* msk;
    unsigned int len;
    const char* label;
    …
    return wolfSSL_make_eap_keys(ssl, msk, len, label);
    \endcode
    \sa wc_PRF
    \sa wc_HmacFinal
    \sa wc_HmacUpdate
*/
int wolfSSL_make_eap_keys(WOLFSSL* ssl, void* key, unsigned int len,
                                                             const char* label);

/*!
    \ingroup IO
    \brief  Writev Semanticsをシミュレートしますが、SSL_Write()の動作のために実際にはブロックしないため、フロント追加が小さくなる可能性があるためWritevを使いやすいソフトウェアに移植する。
    \return >0  成功時に書かれたバイト数。
    \return 0  失敗したときに返されます。特定のエラーコードについてwolfSSL_get_error()を呼び出します。
    \return MEMORY_ERROR  メモリエラーが発生した場合に返されます。
    \return SSL_FATAL_ERROR  エラーが発生したとき、または非ブロッキングソケットを使用するときには、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが受信され、再度WOLFSSL_WRITE()を呼び出す必要がある場合は、障害が発生します。特定のエラーコードを取得するには、wolfSSL_get_error()を使用してください。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param iov  書き込みへのI / Oベクトルの配列

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char *bufA = “hello\n”;
    char *bufB = “hello world\n”;
    int iovcnt;
    struct iovec iov[2];

    iov[0].iov_base = buffA;
    iov[0].iov_len = strlen(buffA);
    iov[1].iov_base = buffB;
    iov[1].iov_len = strlen(buffB);
    iovcnt = 2;
    ...
    ret = wolfSSL_writev(ssl, iov, iovcnt);
    // wrote “ret” bytes, or error if <= 0.
    \endcode
    \sa wolfSSL_write
*/
int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);

/*!
    \ingroup Setup
    \brief  この関数はCA署名者リストをアンロードし、署名者全体のテーブルを解放します。
    \return SSL_SUCCESS  機能の実行に成功したことに戻ります。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がnullの場合、または他の方法では未解決の引数値がサブルーチンに渡された場合に返されます。
    \return BAD_MUTEX_E  ミューテックスエラーが発生した場合に返されます。lockmutex()は0を返しませんでした。

    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    …
    if(!wolfSSL_CTX_UnloadCAs(ctx)){
    	// The function did not unload CAs
    }
    \endcode
    \sa wolfSSL_CertManagerUnloadCAs
    \sa LockMutex
    \sa FreeSignerTable
    \sa UnlockMutex
*/
int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX*);

/*!
    \ingroup Setup
    \brief  この関数は、以前にロードされたすべての信頼できるピア証明書をアンロードするために使用されます。マクロwolfssl_trust_peer_certを定義することで機能が有効になっています。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  CTXがNULLの場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_Unload_trust_peers(ctx);
    if (ret != SSL_SUCCESS) {
        // error unloading trusted peer certs
    }
    ...
    \endcode
    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_trust_peer_cert
*/
int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX*);

/*!
    \ingroup Setup
    \brief  この関数は、TLS / SSLハンドシェイクを実行するときにピアを検証するために使用する証明書をロードします。ハンドシェイク中に送信されたピア証明書は、使用可能なときにスキッドを使用することによって比較されます。これら2つのことが一致しない場合は、ロードされたCASが使用されます。ファイルの代わりにバッファーの場合は、wolfssl_ctx_trust_peer_certと同じ機能です。特徴はマクロwolfssl_trust_peer_certを定義することによって有効になっています適切な使用法の例を参照してください。
    \return SSL_SUCCESS  成功すると
    \return SSL_FAILURE  CTXがNULLの場合、または両方のファイルと種類が無効な場合に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param buffer  証明書を含むバッファへのポインタ。
    \param sz  バッファ入力の長さ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...

    ret = wolfSSL_CTX_trust_peer_buffer(ctx, bufferPtr, bufferSz,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    // error loading trusted peer cert
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_cert
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                  long sz, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数はCA証明書バッファをWolfSSLコンテキストにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。形式バッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。フォーマットがPEM内にある限り、バッファあたり複数のCA証明書をロードすることができます。適切な使用法の例をご覧ください。
    \return SSL_SUCCESS  成功すると
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BUFFER_E  チェーンバッファが受信バッファよりも大きい場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in  CA証明書バッファへのポインタ。
    \param sz  入力CA証明書バッファのサイズ、IN。


    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    ...

    ret = wolfSSL_CTX_load_verify_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs from buffer
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                   long sz, int format);


/*!
    \ingroup CertsKeys
    \brief  この関数はCA証明書バッファをWolfSSLコンテキストにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。形式バッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。フォーマットがPEM内にある限り、バッファあたり複数のCA証明書をロードすることができます。_EXバージョンはPR 2413に追加され、UserChainとFlagsの追加の引数をサポートします。
    \return SSL_SUCCESS  成功すると
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BUFFER_E  チェーンバッファが受信バッファよりも大きい場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in  CA証明書バッファへのポインタ。
    \param sz  入力CA証明書バッファのサイズ、IN。
    \param format  バッファ証明書の形式、SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。
    \param userChain  フォーマットwolfssl_filetype_asn1を使用する場合、このセットはゼロ以外のセットを示しています.Derのチェーンが表示されています。

    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    ...

    // Example for force loading an expired certificate
    ret = wolfSSL_CTX_load_verify_buffer_ex(ctx, certBuff, sz, SSL_FILETYPE_PEM,
        0, (WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY));
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs from buffer
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX* ctx,
                                      const unsigned char* in, long sz,
                                      int format, int userChain, word32 flags);

/*!
    \ingroup CertsKeys
    \brief  この関数は、CA証明書チェーンバッファをWolfSSLコンテキストにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。形式バッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。フォーマットがPEM内にある限り、バッファあたり複数のCA証明書をロードすることができます。適切な使用法の例をご覧ください。
    \return SSL_SUCCESS  成功すると
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BUFFER_E  チェーンバッファが受信バッファよりも大きい場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in  CA証明書バッファへのポインタ。
    \param sz  入力CA証明書バッファのサイズ、IN。

    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    ...

    ret = wolfSSL_CTX_load_verify_chain_buffer_format(ctx,
                         certBuff, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        // error loading CA certs from buffer
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_chain_buffer_format(WOLFSSL_CTX* ctx,
                                               const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は証明書バッファをWolfSSLコンテキストにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。形式バッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。適切な使用法の例をご覧ください。
    \return SSL_SUCCESS  成功すると
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in  ロードする証明書を含む入力バッファ。
    \param sz  入力バッファのサイズ。

    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    ...
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading certificate from buffer
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
                                       const unsigned char* in, long sz,
                                       int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、秘密鍵バッファをSSLコンテキストにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。形式バッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1OR SSL_FILETYPE_PEM。適切な使用法の例をご覧ください。
    \return SSL_SUCCESS  成功すると
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return NO_PASSWORD  鍵ファイルが暗号化されているがパスワードが提供されていない場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in  ロードする秘密鍵を含む入力バッファ。
    \param sz  入力バッファのサイズ。

    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte keyBuff[...];
    ...
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, keyBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading private key from buffer
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx,
                                      const unsigned char* in, long sz,
                                      int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、証明書チェーンバッファをWolfSSLコンテキストにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。バッファはPEM形式で、ルート証明書で終わる対象の証明書から始めてください。適切な使用法の例をご覧ください。
    \return SSL_SUCCESS  成功すると
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BUFFER_E  チェーンバッファが受信バッファよりも大きい場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in  ロードされるPEM形式の証明書チェーンを含む入力バッファ。

    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certChainBuff[...];
    ...
    ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx, certChainBuff, sz);
    if (ret != SSL_SUCCESS) {
    	// error loading certificate chain from buffer
    }
    ...
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX* ctx,
                                             const unsigned char* in, long sz);

/*!
    \ingroup CertsKeys
    \brief  この関数は、証明書バッファをWolfSSLオブジェクトにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。形式バッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。適切な使用法の例をご覧ください。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \param ssl  wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param in  ロードする証明書を含むバッファ。
    \param sz  バッファにある証明書のサイズ。

    _Example_
    \code
    int buffSz;
    int ret;
    byte certBuff[...];
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_use_certificate_buffer(ssl, certBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate from buffer
    }
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_certificate_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、秘密鍵バッファをWolfSSLオブジェクトにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。形式バッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。適切な使用法の例をご覧ください。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return NO_PASSWORD  鍵ファイルが暗号化されているがパスワードが提供されていない場合に返されます。
    \param ssl  wolfssl_new()で作成されたSSLセッションへのポインタ。
    \param in  ロードする秘密鍵を含むバッファ。
    \param sz  バッファにある秘密鍵のサイズ。

    _Example_
    \code
    int buffSz;
    int ret;
    byte keyBuff[...];
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_use_PrivateKey_buffer(ssl, keyBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load private key from buffer
    }
    \endcode
    \sa wolfSSL_use_PrivateKey
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys
    \brief  この関数は、証明書チェーンバッファをWolfSSLオブジェクトにロードします。バッファ以外のバージョンのように動作し、ファイルの代わりに入力としてバッファと呼ばれる機能が異なるだけです。バッファはサイズSZの引数によって提供されます。バッファはPEM形式で、ルート証明書で終わる対象の証明書から始めてください。適切な使用法の例をご覧ください。
    \return SSL_SUCCES  成功時に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BUFFER_E  チェーンバッファが受信バッファよりも大きい場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param in  ロードする証明書を含むバッファ。

    _Example_
    \code
    int buffSz;
    int ret;
    byte certChainBuff[...];
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_use_certificate_chain_buffer(ssl, certChainBuff, buffSz);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate chain from buffer
    }
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
*/
int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl,
                                         const unsigned char* in, long sz);

/*!
    \ingroup CertsKeys
    \brief  この関数は、SSLが所有する証明書または鍵をアンロードします。
    \return SSL_SUCCESS   - 関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG   -  wolfsslオブジェクトがnullの場合に返されます。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    int unloadKeys = wolfSSL_UnloadCertsKeys(ssl);
    if(unloadKeys != SSL_SUCCESS){
	    // Failure case.
    }
    \endcode
    \sa wolfSSL_CTX_UnloadCAs
*/
int wolfSSL_UnloadCertsKeys(WOLFSSL*);

/*!
    \ingroup Setup
    \brief  この機能は、可能な限りハンドシェイクメッセージのグループ化をオンにします。
    \return SSL_SUCCESS  成功に戻ります。
    \return BAD_FUNC_ARG  入力コンテキストがNULLの場合、返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_group_messages(ctx);
    if (ret != SSL_SUCCESS) {
	    // failed to set handshake message grouping
    }
    \endcode
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_new
*/
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX*);

/*!
    \ingroup Setup
    \brief  この機能は、可能な限りハンドシェイクメッセージのグループ化をオンにします。
    \return SSL_SUCCESS  成功に戻ります。
    \return BAD_FUNC_ARG  入力コンテキストがNULLの場合、返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_group_messages(ssl);
    if (ret != SSL_SUCCESS) {
	// failed to set handshake message grouping
    }
    \endcode
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_new
*/
int wolfSSL_set_group_messages(WOLFSSL*);

/*!
    \brief
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param cbf  フォームの関数ポインタであるCallBackFozzerタイプ：int（* callbackfuzzer）（wolfssl * ssl、consigned char * buf、int sz、int型、void * fuzzctx）;
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* fCtx;

    int callbackFuzzerCB(WOLFSSL* ssl, const unsigned char* buf, int sz,
				int type, void* fuzzCtx){
    // function definition
    }
    …
    wolfSSL_SetFuzzerCb(ssl, callbackFuzzerCB, fCtx);
    \endcode
    \sa CallbackFuzzer
*/
void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx);

/*!
    \brief
    \return 0  関数がエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  許容できない値で関数に渡された引数があった場合に返されます。
    \return COOKIE_SECRET_SZ  秘密サイズが0の場合に返されます。
    \return MEMORY_ERROR  新しいCookie Secretにメモリを割り当てる問題がある場合は返されました。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param secret  秘密バッファを表す定数バイトポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const* byte secret;
    word32 secretSz; // size of secret
    …
    if(!wolfSSL_DTLS_SetCookieSecret(ssl, secret, secretSz)){
    	// Code block for failure to set DTLS cookie secret
    } else {
    	// Success! Cookie secret is set.
    }
    \endcode
    \sa ForceZero
    \sa wc_RNG_GenerateBlock
*/
int   wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl,
                                               const unsigned char* secret,
                                               unsigned int secretSz);

/*!
    \brief
    \return rng  成功時に返されます。
    \return NULL  sslがNULLの場合
    _Example_
    \code
    WOLFSSL* ssl;

    wolfSSL_GetRNG(ssl);

    \endcode
    \sa  wolfSSL_CTX_new_rng
*/
WC_RNG* wolfSSL_GetRNG(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は、許可されている最小のダウングレードバージョンを設定します。接続が（wolfsslv23_client_methodまたはwolfsslv23_server_method）を使用して、接続がダウングレードできる場合にのみ適用されます。
    \return SSL_SUCCESS  エラーなしで返された関数と最小バージョンが設定されている場合に返されます。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造がNULLの場合、または最小バージョンがサポートされていない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version; // macrop representation
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
    	// Failed to set min version
    }
    \endcode
    \sa SetMinVersionHelper
*/
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup TLS
    \brief  この関数は、許可されている最小のダウングレードバージョンを設定します。接続が（wolfsslv23_client_methodまたはwolfsslv23_server_method）を使用して、接続がダウングレードできる場合にのみ適用されます。
    \return SSL_SUCCESS  この関数とそのサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  SSLオブジェクトがNULLの場合に返されます。サブルーチンでは、良いバージョンが一致しない場合、このエラーはスローされます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version;  macro representation
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
	    Failed to set min version
    }
    \endcode
    \sa SetMinVersionHelper
*/
int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version);

/*!
    \brief  ビルドオプションと設定に依存します。WolfSSLを構築するときにshow_sizesが定義されている場合、この関数はWolfSSLオブジェクト（スイート、暗号など）内の個々のオブジェクトのサイズもstdoutに印刷されます。
    \return size  この関数は、WolfSSLオブジェクトのサイズを返します。

    _Example_
    \code
    int size = 0;
    size = wolfSSL_GetObjectSize();
    printf(“sizeof(WOLFSSL) = %d\n”, size);
    \endcode
    \sa wolfSSL_new
*/
int wolfSSL_GetObjectSize(void);  /* object size based on build */
/*!
    \brief  アプリケーションがトランスポートレイヤ間で何バイトを送信したい場合は、指定された平文の入力サイズを指定してください。SSL / TLSハンドシェイクが完了した後に呼び出す必要があります。
    \return size  成功すると、要求されたサイズが返されます
    \return INPUT_SIZE_E  入力サイズが最大TLSフラグメントサイズより大きい場合は返されます（WOLFSSL_GETMAXOUTPUTSIZE()）。
    \return BAD_FUNC_ARG  無効な関数引数に戻り、またはSSL / TLSハンドシェイクがまだ完了していない場合
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetMaxOutputSize
*/
int wolfSSL_GetOutputSize(WOLFSSL* ssl, int inSz);

/*!
    \brief  プロトコル規格で指定されている最大SSL / TLSレコードサイズのいずれかに対応します。この関数は、アプリケーションがwolfssl_getOutputSize()と呼ばれ、input_size_eエラーを受信したときに役立ちます。SSL / TLSハンドシェイクが完了した後に呼び出す必要があります。
    \return size  成功すると、最大出力サイズが返されます
    \return BAD_FUNC_ARG  無効な関数引数のときに返されるか、SSL / TLSハンドシェイクがまだ完了していない場合。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetOutputSize
*/
int wolfSSL_GetMaxOutputSize(WOLFSSL*);

/*!
    \ingroup Setup
    \brief  この関数は、バージョンで指定されたバージョンを使用して、指定されたSSLセッション（WolfSSLオブジェクト）のSSL/TLSプロトコルバージョンを設定します。これにより、SSLセッション（SSL）のプロトコル設定が最初に定義され、SSLコンテキスト（wolfSSL_CTX_new()）メソッドの種類によって上書きされます。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  入力SSLオブジェクトがNULLまたは誤ったプロトコルバージョンがバージョンで指定されている場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_SetVersion(ssl, WOLFSSL_TLSV1);
    if (ret != SSL_SUCCESS) {
        // failed to set SSL session protocol version
    }
    \endcode
    \sa wolfSSL_CTX_new
*/
int wolfSSL_SetVersion(WOLFSSL* ssl, int version);

/*!
    \brief  MAC /暗号化コールバック。コールバックは成功の場合は0を返すか、エラーの場合は<0です。SSLとCTXポインタはユーザーの利便性に利用できます。MacOutは、MACの結果を保存する必要がある出力バッファです。MacinはMac入力バッファーとMacinszのサイズを注意しています。MacContentとMacverifyは、Wolfssl_SettlShmacinner()に必要であり、そのまま通過します。Encoutは、暗号化の結果を格納する必要がある出力バッファです。ENCINはENCSZが入力のサイズである間は暗号化する入力バッファです。コールバックの例は、wolfssl / test.h mymacencryptcb()を見つけることができます。
    \return none  返品不可。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX* ctx, CallbackMacEncrypti cb);

/*!
    \brief  CTXへのコールバックコンテキスト。
    \return none  返品不可。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  Mac / Encryptコールバックコンテキストは、wolfssl_setmacencryptx()で保存されていました。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_SetMacEncryptCtx
*/
void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

/*!
    \brief  コールバックを復号化/確認します。コールバックは成功の場合は0を返すか、エラーの場合は<0です。SSLとCTXポインタはユーザーの利便性に利用できます。DECOUTは、復号化の結果を格納する出力バッファです。DECINは暗号化された入力バッファーとDecinszのサイズを注意しています。コンテンツと検証は、WolfSSL_SettlShmacinner()に必要であり、そのまま通過します。PADSZは、パディングの合計値で設定する出力変数です。つまり、MACサイズとパディングバイトとパッドバイトを加えています。コールバックの例は、wolfssl / test.h mydecryptverifycb()を見つけることができます。
    \return none  いいえ返します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX* ctx,
                                               CallbackDecryptVerify cb);

/*!
    \brief  コールバックコンテキストをCTXに復号化/検証します。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_GetDecryptVerifyCtx
*/
void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  wolfssl_setdecryptverifyctx()で以前に保存されているコールバックコンテキストを復号化/検証します。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_SetDecryptVerifyCtx
*/
void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

/*!
    \brief  VERIFYパラメーターは、これがピア・メッセージの検証のためのものであるかどうかを指定します。
    \return pointer  正常にコールが秘密に有効なポインタを返します。秘密のサイズは、Wolfssl_gethmacsize()から入手できます。
    \return NULL  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetHmacSize
*/
const unsigned char* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify);

/*!
    \brief
    \return pointer  正常にコールがキーへの有効なポインタを返します。鍵のサイズは、wolfssl_getkeysize()から取得できます。
    \return NULL  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
*/
const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL*);

/*!
    \brief  ハンドシェイクプロセスから。
    \return pointer  正常にコールがIVへの有効なポインタを返します。IVのサイズは、wolfssl_getCipherBlockSize()から取得できます。
    \return NULL  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetCipherBlockSize()
    \sa wolfSSL_GetClientWriteKey()
*/
const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL*);

/*!
    \brief
    \return pointer  正常にコールが鍵への有効なポインタを返します。鍵のサイズは、wolfssl_getkeysize()から取得できます。
    \return NULL  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetServerWriteIV
*/
const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL*);

/*!
    \brief  ハンドシェイクプロセスから。
    \return pointer  正常にコールがIVへの有効なポインタを返します。IVのサイズは、wolfssl_getCipherBlockSize()から取得できます。
    \return NULL  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetClientWriteKey
*/
const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL*);

/*!
    \brief
    \return size  正常にコールが鍵サイズをバイト単位で返します。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
int                  wolfSSL_GetKeySize(WOLFSSL*);

/*!
    \ingroup CertsKeys
    \brief  WolfSSL構造体に保持されているSpecs構造体のIV_SIZEメンバーを返します。
    \return iv_size  ssl-> specs.iv_sizeで保持されている値を返します。
    \return BAD_FUNC_ARG  WolfSSL構造がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ivSize;
    ...
    ivSize = wolfSSL_GetIVSize(ssl);

    if(ivSize > 0){
    	// ivSize holds the specs.iv_size value.
    }
    \endcode
    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
    \sa wolfSSL_GetServerWriteIV
*/
int                  wolfSSL_GetIVSize(WOLFSSL*);

/*!
    \brief
    \return success  成功した場合、呼び出しがWolfSSLオブジェクトの側面に応じてwolfssl_server_endまたはwolfssl_client_endを返します。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
int                  wolfSSL_GetSide(WOLFSSL*);

/*!
    \brief  少なくともTLSバージョン1.1以上です。
    \return true/false  成功した場合、呼び出しがTRUEまたは0の場合は0を返します。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetSide
*/
int                  wolfSSL_IsTLSv1_1(WOLFSSL*);

/*!
    \brief  ハンドシェイクから。
    \return If  コールが成功すると、wolfssl_cipher_null、wolfssl_des、wolfssl_triple_des、wolfssl_aes、wolfssl_aes_gcm、wolfssl_aes_ccm、wolfssl_camellia。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetBulkCipher(WOLFSSL*);

/*!
    \brief  ハンドシェイク。
    \return size  正常にコールが暗号ブロックサイズのサイズをバイト単位で戻します。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetCipherBlockSize(WOLFSSL*);

/*!
    \brief  ハンドシェーク。暗号タイプのwolfssl_aead_typeの場合。
    \return size  正常にコールがEAD MACサイズのサイズをバイト単位で戻します。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetAeadMacSize(WOLFSSL*);

/*!
    \brief  ハンドシェーク。wolfssl_aead_type以外の暗号タイプの場合。
    \return size  正常にコールが（H）MACサイズのサイズをバイト単位で戻します。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetHmacSize(WOLFSSL*);

/*!
    \brief  ハンドシェーク。wolfssl_aead_type以外の暗号タイプの場合。
    \return If  コールが成功すると、次のいずれかが返されます.MD5、SHA、SHA256、SHA384。
    \return BAD_FUNC_ARG  エラー状態に対して返される可能性があります。
    \return SSL_FATAL_ERROR  エラー状態にも返される可能性があります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacSize
*/
int                  wolfSSL_GetHmacType(WOLFSSL*);

/*!
    \brief  ハンドシェイクから。
    \return If  正常にコールは次のいずれかを返します.WolfSSL_BLOCK_TYPE、WOLFSSL_STREAM_TYPE、WOLFSSL_AEAD_TYPE。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetCipherType(WOLFSSL*);

/*!
    \brief  送受信結果は、少なくともwolfssl_gethmacsize()バイトであるべきである内部に書き込まれます。メッセージのサイズはSZで指定され、内容はメッセージの種類であり、検証はこれがピアメッセージの検証であるかどうかを指定します。wolfssl_aead_typeを除く暗号タイプに有効です。
    \return 1  成功時に返されます。
    \return BAD_FUNC_ARG  エラー状態に戻ります。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int wolfSSL_SetTlsHmacInner(WOLFSSL* ssl, byte* inner,
                            word32 sz, int content, int verify);

/*!
    \brief  コールバックは成功の場合は0を返すか、エラーの場合は<0です。SSLとCTXポインタはユーザーの利便性に利用できます。INSは入力バッファーが入力の長さを表します。OUTは、署名の結果を保存する必要がある出力バッファです。OUTSZは、呼び出し時に出力バッファのサイズを指定する入力/出力変数であり、署名の実際のサイズを戻す前に格納する必要があります。keyderはASN1フォーマットのECC秘密鍵であり、Keyszは鍵のキーの長さです。コールバックの例は、wolfssl / test.h myeccsign()を見つけることができます。
    \return none  いいえ返します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_SetEccSignCtx
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx, CallbackEccSign cb);

/*!
    \brief  CTXへのコンテキスト。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  以前にwolfssl_seteccsignctx()で保存されていたコンテキスト。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_SetEccSignCtx
*/
void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

/*!
    \brief  CTXへのコンテキスト。
    \return none  いいえ返します。
    \param ctx  wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx);

/*!
    \brief  以前にwolfssl_seteccsignctx()で保存されていたコンテキスト。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_SetEccSignCtx
*/
void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx);

/*!
    \brief  コールバックは成功の場合は0を返すか、エラーの場合は<0です。SSLとCTXポインタはユーザーの利便性に利用できます。SIGは検証の署名であり、SIGSZは署名の長さを表します。ハッシュはメッセージのダイジェストを含む入力バッファであり、HASHSZはハッシュの長さを意味します。結果は、検証の結果を格納する出力変数、成功のために1、失敗のために0を記憶する必要があります。keyderはASN1フォーマットのECC秘密鍵であり、Keyszはキーのキーの長さです。コールバックの例は、wolfssl / test.h myeccverify()を見つけることができます。
    \return none  いいえ返します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_SetEccVerifyCtx
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb);

/*!
    \brief  CTXへのコンテキスト。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  以前にwolfssl_setecverifyctx()で保存されていたコンテキスト。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_SetEccVerifyCtx
*/
void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

/*!
    \brief  コールバックは成功の場合は0を返すか、エラーの場合は<0です。SSLとCTXポインタはユーザーの利便性に利用できます。INSは入力バッファーが入力の長さを表します。OUTは、署名の結果を保存する必要がある出力バッファです。OUTSZは、呼び出し時に出力バッファのサイズを指定する入力/出力変数であり、署名の実際のサイズを戻す前に格納する必要があります。keyderはASN1フォーマットのRSA秘密鍵であり、Keyszはバイト数のキーの長さです。コールバックの例は、wolfssl / test.h myrsasign()を見つけることができます。
    \return none  いいえ返します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_SetRsaSignCtx
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb);

/*!
    \brief  ctxに。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  以前にwolfssl_setrsAsignctx()で保存されていたコンテキスト。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_SetRsaSignCtx
*/
void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

/*!
    \brief  コールバックは、成功のための平文バイト数または<0エラーの場合は<0を返すべきです。SSLとCTXポインタはユーザーの利便性に利用できます。SIGは検証の署名であり、SIGSZは署名の長さを表します。復号化プロセスとパディングの後に検証バッファの先頭に設定する必要があります。keyderはASN1形式のRSA公開鍵であり、Keyszはキーのキーの長さです。コールバックの例は、wolfssl / test.h myrsaverify()を見つけることができます。
    \return none  いいえ返します。
    \sa wolfSSL_SetRsaVerifyCtx
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);

/*!
    \brief  CTXへのコンテキスト。
    \return none  いいえ返します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  以前にwolfssl_setrsaverifyctx()で保存されていたコンテキスト。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_SetRsaVerifyCtx
*/
void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

/*!
    \brief  暗号化します。コールバックは成功の場合は0を返すか、エラーの場合は<0です。SSLとCTXポインタはユーザーの利便性に利用できます。INは入力バッファですが、INSZは入力の長さを表します。暗号化の結果を保存する必要がある出力バッファです。OUTSZは、呼び出し時に出力バッファのサイズを指定する入力/出力変数であり、暗号化の実際のサイズは戻って前に格納されるべきです。keyderはASN1形式のRSA公開鍵であり、Keyszはキーのキーの長さです。例コールバックの例は、wolfssl / test.h myrsaenc()を見つけることができます。
    \return none  いいえ返します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_SetRsaEncCtx
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb);

/*!
    \brief  CTXへのコールバックコンテキスト。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  コールバックコンテキストは、wolfssl_setrsaencctx()で以前に保存されていました。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_SetRsaEncCtx
*/
void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/*!
    \brief  復号化します。コールバックは、成功のための平文バイト数または<0エラーの場合は<0を返すべきです。SSLとCTXポインタはユーザーの利便性に利用できます。INは、復号化する入力バッファが入力の長さを表します。復号化プロセスおよび任意のパディングの後、復号化バッファの先頭に設定する必要があります。keyderはASN1フォーマットのRSA秘密鍵であり、Keyszはバイト数のキーの長さです。コールバックの例は、wolfssl / test.h myrsadec()を見つけることができます。
    \return none  いいえ返します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_SetRsaDecCtx
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb);

/*!
    \brief  CTXへのコールバックコンテキスト。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief  コールバックコンテキストは、wolfssl_setrsadecctx()で以前に保存されていました。
    \return pointer  正常にコールがコンテキストへの有効なポインタを返します。
    \return NULL  空白のコンテキストのために返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_SetRsaDecCtx
*/
void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);

/*!
    \brief  新しいCA証明書がWolfSSLにロードされたときに呼び出される（WolfSSL_CTX）。コールバックには、符号化された証明書を持つバッファが与えられます。
    \return none  返品不可。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;

    // CA callback prototype
    int MyCACallback(unsigned char *der, int sz, int type);

    // Register the custom CA callback with the SSL context
    wolfSSL_CTX_SetCACb(ctx, MyCACallback);

    int MyCACallback(unsigned char* der, int sz, int type)
    {
    	// custom CA callback function, DER-encoded cert
        // located in “der” of size “sz” with type “type”
    }
    \endcode
    \sa wolfSSL_CTX_load_verify_locations
*/
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb);

/*!
    \ingroup CertManager
    \brief  新しい証明書マネージャコンテキストを割り当てて初期化します。このコンテキストは、SSLのニーズとは無関係に使用できます。証明書をロードしたり、証明書を確認したり、失効状況を確認したりするために使用することができます。
    \return WOLFSSL_CERT_MANAGER  正常にコールが有効なwolfssl_cert_managerポインタを返します。
    \return NULL  エラー状態に戻ります。
    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);

/*!
    \ingroup CertManager
    \brief  新しい証明書マネージャコンテキストを割り当てて初期化します。このコンテキストは、SSLのニーズとは無関係に使用できます。証明書をロードしたり、証明書を確認したり、失効状況を確認したりするために使用することができます。
    \return WOLFSSL_CERT_MANAGER  正常にコールが有効なwolfssl_cert_managerポインタを返します。
    \return NULL  エラー状態に戻ります。

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
	// error creating new cert manager
    }
    \endcode
    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);

/*!
    \ingroup CertManager
    \brief  証明書マネージャのコンテキストに関連付けられているすべてのリソースを解放します。証明書マネージャを使用する必要がなくなるときにこれを呼び出します。
    \return none

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    ...
    wolfSSL_CertManagerFree(cm);
    \endcode
    \sa wolfSSL_CertManagerNew
*/
void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief  ManagerコンテキストへのCA証明書のロードの場所を指定します。PEM証明書カフェイルには、複数の信頼できるCA証明書が含まれている可能性があります。capathがnullでない場合、PEM形式のCA証明書を含むディレクトリを指定します。
    \return SSL_SUCCESS  成功した場合に返されます。、通話が戻ります。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BAD_FUNC_ARG  ポインタが提供されていない場合に返されるエラーです。
    \return SSL_FATAL_ERROR   - 失敗時に返されます。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。
    \param file  ロードするCA証明書を含むファイルの名前へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerLoadCA(cm, “path/to/cert-file.pem”, 0);
    if (ret != SSL_SUCCESS) {
	// error loading CA certs into cert manager
    }
    \endcode
    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                 const char* d);

/*!
    \ingroup CertManager
    \brief  wolfssl_ctx_load_verify_bufferを呼び出して、関数に渡されたCM内の情報を失うことなく一時的なCMを使用してその結果を返すことによってCAバッファをロードします。
    \return SSL_FATAL_ERROR  wolfssl_cert_manager構造体がNULLの場合、またはwolfSSL_CTX_new()がNULLを返す場合に返されます。
    \return SSL_SUCCESS  実行が成功するために返されます。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。
    \param in  CERT情報用のバッファー。
    \param sz  バッファの長さ。

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    …
    const unsigned char* in;
    long sz;
    int format;
    …
    if(wolfSSL_CertManagerLoadCABuffer(vp, sz, format) != SSL_SUCCESS){
	    Error returned. Failure case code block.
    }
    \endcode
    \sa wolfSSL_CTX_load_verify_buffer
    \sa ProcessChainBuffer
    \sa ProcessBuffer
    \sa cm_pick_method
*/
int wolfSSL_CertManagerLoadCABuffer(WOLFSSL_CERT_MANAGER* cm,
                                  const unsigned char* in, long sz, int format);

/*!
    \ingroup CertManager
    \brief  この関数はCA署名者リストをアンロードします。
    \return SSL_SUCCESS  機能の実行に成功したことに戻ります。
    \return BAD_FUNC_ARG  wolfssl_cert_managerがnullの場合に返されます。
    \return BAD_MUTEX_E  ミューテックスエラーが発生した場合に返されます。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    if(wolfSSL_CertManagerUnloadCAs(ctx->cm) != SSL_SUCCESS){
    	Failure case.
    }
    \endcode
    \sa FreeSignerTable
    \sa UnlockMutex
*/
int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief  関数は信頼できるピアリンクリストを解放し、信頼できるピアリストのロックを解除します。
    \return SSL_SUCCESS  関数が正常に完了した場合
    \return BAD_FUNC_ARG  wolfssl_cert_managerがnullの場合
    \return BAD_MUTEX_E  ミューテックスエラーTPLOCKでは、WOLFSSL_CERT_MANAGER構造体のメンバーは0（ニル）です。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    if(wolfSSL_CertManagerUnload_trust_peers(cm) != SSL_SUCCESS){
	    The function did not execute successfully.
    }
    \endcode
    \sa UnLockMutex
*/
int wolfSSL_CertManagerUnload_trust_peers(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief  証明書マネージャのコンテキストで確認する証明書を指定します。フォーマットはSSL_FILETYPE_PEMまたはSSL_FILETYPE_ASN1にすることができます。
    \return SSL_SUCCESS  成功した場合に返されます。
    \return ASN_SIG_CONFIRM_E  署名が検証できなかった場合に返されます。
    \return ASN_SIG_OID_E  署名の種類がサポートされていない場合に返されます。
    \return CRL_CERT_REVOKED  この証明書が取り消された場合に返されるエラーです。
    \return CRL_MISSING  現在の発行者CRLが利用できない場合に返されるエラーです。
    \return ASN_BEFORE_DATE_E  現在の日付が前日の前にある場合に返されます。
    \return ASN_AFTER_DATE_E  現在の日付が後の日付の後の場合に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BAD_FUNC_ARG  ポインタが提供されていない場合に返されるエラーです。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。
    \param fname  検証する証明書を含むファイルの名前へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerVerify(cm, “path/to/cert-file.pem”,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    error verifying certificate
    }
    \endcode
    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerifyBuffer
*/
int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                    int format);

/*!
    \ingroup CertManager
    \brief  証明書マネージャのコンテキストを使用して確認する証明書バッファを指定します。フォーマットはSSL_FILETYPE_PEMまたはSSL_FILETYPE_ASN1にすることができます。
    \return SSL_SUCCESS  成功した場合に返されます。
    \return ASN_SIG_CONFIRM_E  署名が検証できなかった場合に返されます。
    \return ASN_SIG_OID_E  署名の種類がサポートされていない場合に返されます。
    \return CRL_CERT_REVOKED  この証明書が取り消された場合に返されるエラーです。
    \return CRL_MISSING  現在の発行者CRLが利用できない場合に返されるエラーです。
    \return ASN_BEFORE_DATE_E  現在の日付が前日の前にある場合に返されます。
    \return ASN_AFTER_DATE_E  現在の日付が後の日付の後の場合に返されます。
    \return SSL_BAD_FILETYPE  ファイルが間違った形式である場合に返されます。
    \return SSL_BAD_FILE  ファイルが存在しない場合に返されます。読み込め、または破損していません。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E  base16デコードがファイルに対して失敗した場合に返されます。
    \return BAD_FUNC_ARG  ポインタが提供されていない場合に返されるエラーです。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。
    \param buff  検証する証明書を含むバッファ。
    \param sz  バッファのサイズ、BUF。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    int sz = 0;
    WOLFSSL_CERT_MANAGER* cm;
    byte certBuff[...];
    ...

    ret = wolfSSL_CertManagerVerifyBuffer(cm, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	error verifying certificate
    }

    \endcode
    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* buff, long sz, int format);

/*!
    \ingroup CertManager
    \brief  この関数は、証明書マネージャーのverifyCallback関数を設定します。存在する場合、それはロードされた各CERTに対して呼び出されます。検証エラーがある場合は、検証コールバックを使用してエラーを過度に乗り越えます。
    \return none  返品不可。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
    { // do custom verification of certificate }

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    wolfSSL_CertManagerSetVerify(cm, myVerify);

    \endcode
    \sa wolfSSL_CertManagerVerify
*/
void wolfSSL_CertManagerSetVerify(WOLFSSL_CERT_MANAGER* cm,
                                                             VerifyCallback vc);

/*!
    \brief  CRLリスト。
    \return SSL_SUCCESS  関数が予想どおりに返された場合は返します。wolfssl_cert_manager構造体のCRLENABLEDメンバーがオンになっている場合。
    \return MEMORY_E  割り当てられたメモリが失敗した場合は返します。
    \return BAD_FUNC_ARG  wolfssl_cert_managerがnullの場合
    \param cm  wolfssl_cert_manager構造体へのポインタ。
    \param der  DERフォーマット証明書へのポインタ。

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm;
    byte* der;
    int sz; // size of der
    ...
    if(wolfSSL_CertManagerCheckCRL(cm, der, sz) != SSL_SUCCESS){
    	// Error returned. Deal with failure case.
    }
    \endcode
    \sa CheckCertCRL
    \sa ParseCertRelative
    \sa wolfSSL_CertManagerSetCRL_CB
    \sa InitDecodedCert
*/
int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER* cm,
                                unsigned char* der, int sz);

/*!
    \ingroup CertManager
    \brief  証明書マネージャを使用して証明書を検証するときに証明書失効リストの確認をオンにします。デフォルトでは、CRLチェックはオフです。オプションには、wolfssl_crl_checkallが含まれます。これは、チェーン内の各証明書に対してCRL検査を実行します。これはデフォルトであるリーフ証明書のみです。
    \return SSL_SUCCESS  成功した場合に返されます。、通話が戻ります。
    \return NOT_COMPILED_IN  WolfSSLがCRLを有効にして構築されていない場合に返されます。
    \return MEMORY_E  メモリ不足状態が発生した場合に返されます。
    \return BAD_FUNC_ARG  ポインタが提供されていない場合に返されるエラーです。
    \return SSL_FAILURE  CRLコンテキストを正しく初期化できない場合に返されます。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerEnableCRL(cm, 0);
    if (ret != SSL_SUCCESS) {
    	error enabling cert manager
    }

    ...
    \endcode
    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief  証明書マネージャを使用して証明書を検証するときに証明書失効リストの確認をオフにします。デフォルトでは、CRLチェックはオフです。この関数を使用して、このCertificate Managerコンテキストを使用してCRL検査を一時的または恒久的に無効にして、以前はCRL検査が有効になっていました。
    \return SSL_SUCCESS  成功した場合に返されます。、通話が戻ります。
    \return BAD_FUNC_ARG  関数ポインタが提供されていない場合に返されるエラーです。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerDisableCRL(cm);
    if (ret != SSL_SUCCESS) {
    	error disabling cert manager
    }
    ...
    \endcode
    \sa wolfSSL_CertManagerEnableCRL
*/
int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief  証明書の失効確認のために証明書をCRLにロードする際にエラーチェックを行い、その後証明書をLoadCRL()へ渡します。

    \return SSL_SUCCESS  wolfSSL_CertManagerLoadCRLでエラーが発生せず、loadCRLが成功で戻る場合に返されます。
    \return BAD_FUNC_ARG  WOLFSSL_CERT_MANAGER構造体がNULLの場合
    \return SSL_FATAL_ERROR  wolfSSL_CertManagerEnableCRLがSSL_SUCCESS以外のを返す場合。
    \return BAD_PATH_ERROR  pathがNULLの場合
    \return MEMORY_E  LOADCRLがヒープメモリの割り当てに失敗した場合。
    \param cm  wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param path  CRLへのパスを保持しているバッファーへのポインタ。
    \param type  ロードする証明書の種類。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type,
    int monitor);
    …
    wolfSSL_CertManagerLoadCRL(SSL_CM(ssl), path, type, monitor);
    \endcode
    \sa wolfSSL_CertManagerEnableCRL
    \sa wolfSSL_LoadCRL
*/
int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER* cm,
                               const char* path, int type, int monitor);

/*!
    \ingroup CertManager
    \brief  この関数は、BufferLoadCRLを呼び出すことによってCRLファイルをロードします。
    \return SSL_SUCCESS  関数がエラーなしで完了した場合に返されます。
    \return BAD_FUNC_ARG  wolfssl_cert_managerがnullの場合に返されます。
    \return SSL_FATAL_ERROR  wolfssl_cert_managerに関連付けられているエラーがある場合に返されます。
    \param cm  wolfssl_cert_manager構造体へのポインタ。
    \param buff  定数バイトタイプとバッファです。
    \param sz  バッファのサイズを表す長いint。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    const unsigned char* buff;
    long sz; size of buffer
    int type;  cert type
    ...
    int ret = wolfSSL_CertManagerLoadCRLBuffer(cm, buff, sz, type);
    if(ret == SSL_SUCCESS){
	return ret;
    } else {
    	Failure case.
    }
    \endcode
    \sa BufferLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
*/
int wolfSSL_CertManagerLoadCRLBuffer(WOLFSSL_CERT_MANAGER* cm,
                                     const unsigned char* buff, long sz,
                                     int type);

/*!
    \ingroup CertManager
    \brief  この関数はCRL証明書マネージャコールバックを設定します。LABE_CRLが定義されていて一致するCRLレコードが見つからない場合、CBMissingCRLは呼び出されます（WolfSSL_CertManagerSetCRL_CBを介して設定）。これにより、CRLを外部に検索してロードすることができます。
    \return SSL_SUCCESS  関数とサブルーチンの実行が成功したら返されます。
    \return BAD_FUNC_ARG  wolfssl_cert_manager構造体がNULLの場合に返されます。
    \param cm  証明書の情報を保持しているWOLFSSL_CERT_MANAGER構造。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url){
	    Function body.
    }
    …
    CbMissingCRL cb = CbMissingCRL;
    …
    if(ctx){
        return wolfSSL_CertManagerSetCRL_Cb(SSL_CM(ssl), cb);
    }
    \endcode
    \sa CbMissingCRL
    \sa wolfSSL_SetCRL_Cb
*/
int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER* cm,
                                 CbMissingCRL cb);
/*!
    \ingroup CertManager
    \brief この関数は証明書マネジャーに保持されているCRLを解放します。
    アプリケーションはCRLをwolfSSL_CertManagerFreeCRLを呼び出して解放した後に、新しいCRLをロードすることができます。

    \return SSL_SUCCESS 関数の実行に成功した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体へのポインターがNULLで渡された場合に返されます。

    \param cm wolfSSL_CertManagerNew()で生成されたWOLFSSL_CERT_MANAGER構造体へのポインター。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    const char* crl1     = "./certs/crl/crl.pem";
    WOLFSSL_CERT_MANAGER* cm = NULL;

    cm = wolfSSL_CertManagerNew();
    wolfSSL_CertManagerLoadCRL(cm, crl1, WOLFSSL_FILETYPE_PEM, 0);
    …
    wolfSSL_CertManagerFreeCRL(cm);
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
*/
int wolfSSL_CertManagerFreeCRL(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief  この機能により、OCSPENABLED OCSPENABLEDがOCSPチェックオプションが有効になっていることを意味します。
    \return SSL_SUCCESS  機能の実行に成功したことに戻ります。wolfssl_cert_managerのOCSPENABLEDメンバーが有効になっています。
    \return BAD_FUNC_ARG  wolfssl_cert_manager構造体がnullの場合、または許可されていない引数値がサブルーチンに渡された場合に返されます。
    \return MEMORY_E  この関数内にメモリを割り当てるエラーまたはサブルーチンがある場合に返されます。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。
    \param der  証明書へのバイトポインタ。

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* der;
    int sz; size of der
    ...
    if(wolfSSL_CertManagerCheckOCSP(cm, der, sz) != SSL_SUCCESS){
	 Failure case.
    }
    \endcode
    \sa ParseCertRelative
    \sa CheckCertOCSP
*/
int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER* cm,
                                 unsigned char* der, int sz);

/*!
    \ingroup CertManager
    \brief  OCSPがオフになっている場合はOCSPをオンにし、[設定]オプションを使用可能になっている場合。
    \return SSL_SUCCESS  関数呼び出しが成功した場合に返されます。
    \return BAD_FUNC_ARG  cm構造体がnullの場合
    \return MEMORY_E  wolfssl_ocsp struct値がnullの場合
    \return SSL_FAILURE  WOLFSSL_OCSP構造体の初期化は初期化に失敗します。
    \return NOT_COMPILED_IN  正しい機能を有効にしてコンパイルされていないビルド。
    \param cm  wolfssl_certmanagernew()を使用して作成されたwolfssl_cert_manager構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    int options;
    …
    if(wolfSSL_CertManagerEnableOCSP(SSL_CM(ssl), options) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode
    \sa wolfSSL_CertManagerNew
*/
int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief  OCSP証明書の失効を無効にします。
    \return SSL_SUCCESS  WolfSSL_CertMangerDisableCRLは、WolfSSL_CERT_MANAGER構造体のCRLEnabledメンバを無効にしました。
    \return BAD_FUNC_ARG  WOLFSSL構造はヌルでした。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CertManagerDisableOCSP(ssl) != SSL_SUCCESS){
	    Fail case.
    }
    \endcode
    \sa wolfSSL_DisableCRL
*/
int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief  この関数は、URLをwolfssl_cert_manager構造体のOCSpoverrideURLメンバーにコピーします。
    \return SSL_SUCCESS  この機能は期待どおりに実行できました。
    \return BAD_FUNC_ARG  wolfssl_cert_manager構造体はnullです。
    \return MEMEORY_E  証明書マネージャのOCSPoverRideURLメンバーにメモリを割り当てることができませんでした。

    _Example_
    \code
    #include <wolfssl/ssl.h>
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    const char* url;
    …
    int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
    …
    if(wolfSSL_CertManagerSetOCSPOverrideURL(SSL_CM(ssl), url) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode
    \sa ocspOverrideURL
    \sa wolfSSL_SetOCSP_OverrideURL
*/
int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER* cm,
                                          const char* url);

/*!
    \ingroup CertManager
    \brief  この関数は、wolfssl_cert_managerのOCSPコールバックを設定します。
    \return SSL_SUCCESS  実行に成功したことに戻ります。引数はwolfssl_cert_manager構造体に保存されます。
    \return BAD_FUNC_ARG  wolfssl_cert_managerがnullの場合に返されます。
    \param cm  wolfssl_cert_manager構造体へのポインタ。
    \param ioCb  CBocSpio型の関数ポインタ。
    \param respFreeCb   -  CBOCSPRESPFREAS型の関数ポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb,
    CbOCSPRespFree respFreeCb, void* ioCbCtx){
    …
    return wolfSSL_CertManagerSetOCSP_Cb(SSL_CM(ssl), ioCb, respFreeCb, ioCbCtx);
    \endcode
    \sa wolfSSL_CertManagerSetOCSPOverrideURL
    \sa wolfSSL_CertManagerCheckOCSP
    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa wolfSSL_ENableOCSP
    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_SetOCSP_Cb
*/
int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER* cm,
                                  CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                                  void* ioCbCtx);

/*!
    \ingroup CertManager
    \brief  この関数は、オプションをオンにしないとOCSPステープルをオンにします。オプションを設定します。
    \return SSL_SUCCESS  エラーがなく、関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG  wolfssl_cert_manager構造体がNULLまたはそうでない場合は、サブルーチンに渡された未解決の引数値があった場合に返されます。
    \return MEMORY_E  メモリ割り当てがある問題が発生した場合に返されます。
    \return SSL_FAILURE  OCSP構造体の初期化が失敗した場合に返されます。
    \return NOT_COMPILED_IN  wolfsslがhaber_certificate_status_requestオプションでコンパイルされていない場合に返されます。

    _Example_
    \code
    int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx){
    …
    return wolfSSL_CertManagerEnableOCSPStapling(ctx->cm);
    \endcode
    \sa wolfSSL_CTX_EnableOCSPStapling
*/
int wolfSSL_CertManagerEnableOCSPStapling(
                                                      WOLFSSL_CERT_MANAGER* cm);

/*!
    \brief
    \return SSL_SUCCESS  関数とサブルーチンはエラーなしで返されました。
    \return BAD_FUNC_ARG  WolfSSL構造がNULLの場合に返されます。
    \return MEMORY_E  メモリの割り当てが失敗した場合に返されます。
    \return SSL_FAILURE  initcrl関数が正常に戻されない場合に返されます。
    \return NOT_COMPILED_IN  have_crlはコンパイル中に有効になっていませんでした。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_EnableCRL(ssl, WOLFSSL_CRL_CHECKALL) != SSL_SUCCESS){
	    // Failure case. SSL_SUCCESS was not returned by this function or
    a subroutine
    }
    \endcode
    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
*/
int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);

/*!
    \brief
    \return SSL_SUCCESS  WolfSSL_CertMangerDisableCRLは、WolfSSL_CERT_MANAGER構造体のCRLEnabledメンバを無効にしました。
    \return BAD_FUNC_ARG  WOLFSSL構造はヌルでした。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_DisableCRL(ssl) != SSL_SUCCESS){
    	// Failure case
    }
    \endcode
    \sa wolfSSL_CertManagerDisableCRL
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableCRL(WOLFSSL* ssl);

/*!
    \brief  失効検査の証明書
    \return WOLFSSL_SUCCESS  関数とすべてのサブルーチンがエラーなしで実行された場合に返されます。
    \return SSL_FATAL_ERROR  サブルーチンの1つが正常に戻されない場合に返されます。
    \return BAD_FUNC_ARG  wolfssl_cert_managerまたはwolfssl構造がnullの場合
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param path  CRLファイルへのパスを保持する定数文字ポインタ。
    \param type  証明書の種類を表す整数。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* crlPemDir;
    …
    if(wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS){
    	// Failure case. Did not return SSL_SUCCESS.
    }
    \endcode
    \sa wolfSSL_CertManagerLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
    \sa LoadCRL
*/
int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor);

/*!
    \brief
    \return SSL_SUCCESS  関数またはサブルーチンがエラーなしで実行された場合に返されます。wolfssl_cert_managerのCBMissingCRLメンバーが設定されています。
    \return BAD_FUNC_ARG  WOLFSSLまたはWOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url) // required signature
    {
    	// Function body
    }
    …
    int crlCb = wolfSSL_SetCRL_Cb(ssl, cb);
    if(crlCb != SSL_SUCCESS){
    	// The callback was not set properly
    }
    \endcode
    \sa CbMissingCRL
    \sa wolfSSL_CertManagerSetCRL_Cb
*/
int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb);

/*!
    \brief
    \return SSL_SUCCESS  関数とサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  この関数またはサブルーチンの引数が無効な引数値を受信した場合に返されます。
    \return MEMORY_E  構造体やその他の変数にメモリを割り当てるエラーが発生した場合に返されます。
    \return NOT_COMPILED_IN  wolfsslがhane_ocspオプションでコンパイルされていない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int options; // initialize to option constant
    …
    int ret = wolfSSL_EnableOCSP(ssl, options);
    if(ret != SSL_SUCCESS){
    	// OCSP is not enabled
    }
    \endcode
    \sa wolfSSL_CertManagerEnableOCSP
*/
int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options);

/*!
    \brief
    \return SSL_SUCCESS  関数とそのサブルーチンがエラーなしで戻った場合に返されます。wolfssl_cert_manager構造体のOCSPENABLEDメンバーは正常に設定されました。
    \return BAD_FUNC_ARG  WolfSSL構造がNULLの場合に返されます。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(wolfSSL_DisableOCSP(ssl) != SSL_SUCCESS){
	    // Returned with an error. Failure case in this block.
    }
    \endcode
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableOCSP(WOLFSSL*);

/*!
    \brief  wolfssl_cert_manager構造体。
    \return SSL_SUCCESS  機能の実行に成功したことに戻ります。
    \return BAD_FUNC_ARG  wolfssl構造体がnullの場合、または未解決の引数がサブルーチンに渡された場合に返されます。
    \return MEMORY_E  サブルーチンにメモリを割り当てるエラーが発生した場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char url[URLSZ];
    ...
    if(wolfSSL_SetOCSP_OverrideURL(ssl, url)){
    	// The override url is set to the new value
    }
    \endcode
    \sa wolfSSL_CertManagerSetOCSPOverrideURL
*/
int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url);

/*!
    \brief  wolfssl_cert_manager構造体。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。CMのOCSPIOCB、OCSPRESPFREECB、およびOCSPIOCTXメンバーが設定されています。
    \return BAD_FUNC_ARG  WOLFSSLまたはWOLFSSL_CERT_MANAGER構造がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param ioCb  CBocSpioを入力するための関数ポインタ。
    \param respFreeCb  応答メモリを解放するための呼び出しであるCBocSpreSpFreeを入力するための関数ポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int OCSPIO_CB(void* , const char*, int , unsigned char* , int,
    unsigned char**){  // must have this signature
    // Function Body
    }
    …
    void OCSPRespFree_CB(void* , unsigned char* ){ // must have this signature
    	// function body
    }
    …
    void* ioCbCtx;
    CbOCSPRespFree CB_OCSPRespFree;

    if(wolfSSL_SetOCSP_Cb(ssl, OCSPIO_CB( pass args ), CB_OCSPRespFree,
				ioCbCtx) != SSL_SUCCESS){
	    // Callback not set
    }
    \endcode
    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                       void* ioCbCtx);

/*!
    \brief
    \return SSL_SUCCESS  この関数とそれがサブルーチンの場合はエラーなしで実行されます。
    \return BAD_FUNC_ARG  CTX構造体がNULLの場合、またはその他の点ではサブルーチンに無効な引数があった場合に返されます。
    \return MEMORY_E  関数の実行中にメモリの割り当てエラーが発生した場合に返されます。
    \return SSL_FAILURE  wolfssl_cert_managerのCRLメンバーが正しく初期化されなかった場合に返されます。
    \return NOT_COMPILED_IN  wolfsslはhane_crlオプションでコンパイルされませんでした。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_EnableCRL(ssl->ctx, options) != SSL_SUCCESS){
    	// The function failed
    }
    \endcode
    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
    \sa wolfSSL_CTX_DisableCRL
*/
int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);

/*!
    \brief
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。wolfssl_cert_manager構造体のCRLEnabledメンバーは0に設定されています。
    \return BAD_FUNC_ARG  CTX構造体またはCM構造体にNULL値がある場合に返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_DisableCRL(ssl->ctx) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode
    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);

/*!
    \brief  wolfssl_certmanagerLoadcr()。
    \return SSL_SUCCESS   - 関数とそのサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG   - この関数またはサブルーチンがNULL構造に渡された場合に返されます。
    \return BAD_PATH_ERROR   - パス変数がnullとして開くと戻ります。
    \return MEMORY_E   - メモリの割り当てが失敗した場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param path  証明書へのパス。
    \param type  証明書の種類を保持する整数変数。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    const char* path;
    …
    return wolfSSL_CTX_LoadCRL(ctx, path, SSL_FILETYPE_PEM, 0);
    \endcode
    \sa wolfSSL_CertManagerLoadCRL
    \sa LoadCRL
*/
int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path, int type, int monitor);

/*!
    \brief  wolfssl_certmanagersetCRL_CBを呼び出して、WolfSSL_CERT_MANAGER構造のメンバー。
    \return SSL_SUCCESS  実行が成功するために返されました。WOLFSSL_CERT_MANAGER構造体のCBMSSINGCRLはCBに正常に設定されました。
    \return BAD_FUNC_ARG  wolfssl_ctxまたはwolfssl_cert_managerがNULLの場合に返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    void cb(const char* url) // Required signature
    {
    	// Function body
    }
    …
    if (wolfSSL_CTX_SetCRL_Cb(ctx, cb) != SSL_SUCCESS){
    	// Failure case, cb was not set correctly.
    }
    \endcode
    \sa wolfSSL_CertManagerSetCRL_Cb
    \sa CbMissingCRL
*/
int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb);

/*!
    \brief  wolfsslの機能オプションの値が1つ以上のオプションで構成されている場合は、次のオプションを1つ以上にします.wolfssl_ocsp_enable  -  OCSPルックアップを有効にするwolfssl_ocsp_url_override  - 証明書のURLの代わりにURLをオーバーライドします。オーバーライドURLは、wolfssl_ctx_setocsp_overrideURL()関数を使用して指定されます。この関数は、wolfsslがOCSPサポート（--enable-ocsp、#define hane_ocsp）でコンパイルされたときにのみOCSPオプションを設定します。
    \return SSL_SUCCESS  成功したときに返されます。
    \return SSL_FAILURE  失敗したときに返されます。
    \return NOT_COMPILED_IN  この関数が呼び出されたときに返されますが、wolfsslがコンパイルされたときにOCSPサポートは有効になっていませんでした。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_OCSP_set_options(ctx, WOLFSSL_OCSP_ENABLE);
    \endcode
    \sa wolfSSL_CTX_OCSP_set_override_url
*/
int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options);

/*!
    \brief  wolfssl_cert_manager構造体のOCSPENABLEDメンバーに影響を与えます。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。CMのOCSPENABLEDメンバーは無効になっています。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造がnullの場合に返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(!wolfSSL_CTX_DisableOCSP(ssl->ctx)){
    	// OCSP is not disabled
    }
    \endcode
    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX*);

/*!
    \brief  wolfssl_csp_url_overrideオプションがwolfssl_ctx_enableocspを使用して設定されていない限り、OCSPは個々の証明書にあるURLを使用します。
    \return SSL_SUCCESS  成功したときに返されます。
    \return SSL_FAILURE  失敗したときに返されます。
    \return NOT_COMPILED_IN  この関数が呼び出されたときに返されますが、wolfsslがコンパイルされたときにOCSPサポートは有効になっていませんでした。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_OCSP_set_override_url(ctx, “custom-url-here”);
    \endcode
    \sa wolfSSL_CTX_OCSP_set_options
*/
int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url);

/*!
    \brief
    \return SSL_SUCCESS  関数が正常に実行された場合に返されます。CM内のOCSPIOCB、OCSPRESPFREECB、およびOCSPIOCTXメンバーは正常に設定されました。
    \return BAD_FUNC_ARG  WOLFSSL_CTXまたはwolfssl_cert_manager構造体がnullの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param ioCb  関数ポインタであるCBocSpio型。
    \param respFreeCb  関数ポインタであるCBocSprepSprepFree型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    CbOCSPIO ocspIOCb;
    CbOCSPRespFree ocspRespFreeCb;
    …
    void* ioCbCtx;

    int isSetOCSP = wolfSSL_CTX_SetOCSP_Cb(ctx, ocspIOCb,
    ocspRespFreeCb, ioCbCtx);

    if(isSetOCSP != SSL_SUCCESS){
    	// The function did not return successfully.
    }
    \endcode
    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx,
                           CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                           void* ioCbCtx);

/*!
    \brief  wolfssl_certmanagerEnableOcspStapling()。
    \return SSL_SUCCESS  エラーがなく、関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造体がNULLまたはそうでない場合は、サブルーチンに渡された未解決の引数値があった場合に返されます。
    \return MEMORY_E  メモリ割り当てがある問題が発生した場合に返されます。
    \return SSL_FAILURE  OCSP構造体の初期化が失敗した場合に返されます。
    \return NOT_COMPILED_IN  wolfsslがhaber_certificate_status_requestオプションでコンパイルされていない場合に返されます。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new();
    ssl->method.version; // set to desired protocol
    ...
    if(!wolfSSL_CTX_EnableOCSPStapling(ssl->ctx)){
    	// OCSP stapling is not enabled
    }
    \endcode
    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa InitOCSP
*/
int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX*);

/*!
    \ingroup CertsKeys
    \brief  通常、SSLハンドシェイクの最後に、WolfSSLは一時的なアレイを解放します。ハンドシェイクが始まる前にこの関数を呼び出すと、WolfSSLは一時的な配列を解放するのを防ぎます。Wolfssl_get_keys()またはPSKのヒントなどのものには、一時的な配列が必要になる場合があります。ユーザが一時的な配列で行われると、wolfssl_freearray()のいずれかが即座にリソースを解放することができ、あるいは、関連するSSLオブジェクトが解放されたときにリソースが解放されるようになる可能性がある。
    \return none  返品不可。

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_KeepArrays(ssl);
    \endcode
    \sa wolfSSL_FreeArrays
*/
void wolfSSL_KeepArrays(WOLFSSL*);

/*!
    \ingroup CertsKeys
    \brief  通常、SSLハンドシェイクの最後に、WolfSSLは一時的なアレイを解放します。wolfssl_keeparrays()がハンドシェイクの前に呼び出された場合、WolfSSLは一時的な配列を解放しません。この関数は一時的な配列を明示的に解放し、ユーザーが一時的な配列で行われたときに呼び出されるべきであり、SSLオブジェクトがこれらのリソースを解放するのを待ったくない。
    \return none  返品不可。

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_FreeArrays(ssl);
    \endcode
    \sa wolfSSL_KeepArrays
*/
void wolfSSL_FreeArrays(WOLFSSL*);

/*!
    \brief  'ssl'パラメータに渡されたオブジェクト。これは、WolfSSLクライアントによってSNI拡張機能がClientHelloで送信され、WolfSSL ServerはServerHello + SNIまたはSNIミスマッチの場合は致命的なAlert Hello + SNIを応答します。
    \return WOLFSSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合で返されるエラーです.SSLはNULL、データはNULL、タイプは不明な値です。（下記参照）
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。
    \param ssl  wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param type  どの種類のサーバー名がデータに渡されたかを示します。既知の型は次のとおりです。enum {wolfssl_sni_host_name = 0};
    \param data  サーバー名データへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseSNI
*/
int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief  SSLコンテキストから作成されたオブジェクトは 'ctx'パラメータに渡されました。これは、WolfSSLクライアントによってSNI拡張機能がClientHelloで送信され、WolfSSLサーバーはServerHello + SNIまたはSNIの不一致の場合には致命的なALERT Hello + SNIを応答します。
    \return WOLFSSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合で返されるエラーです.CTXはNULL、データはNULL、タイプは不明な値です。（下記参照）
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param type  どの種類のサーバー名がデータに渡されたかを示します。既知の型は次のとおりです。enum {wolfssl_sni_host_name = 0};
    \param data  サーバー名データへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSNI
*/
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief  'ssl'パラメータに渡されたSSLオブジェクト内のサーバー名表示を使用したSSLセッションの動作。オプションを以下に説明します。
    \return none  いいえ返します。
    \param ssl  wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param type  どの種類のサーバー名がデータに渡されたかを示します。既知の型は次のとおりです。enum {wolfssl_sni_host_name = 0};
    \param options  選択されたオプションを持つビット単位のセマフォ。利用可能なオプションは次のとおりです。enum {wolfssl_sni_continue_on_mismatch = 0x01、wolfssl_sni_answer_on_mismatch = 0x02};通常、サーバーは、クライアントによって提供されたホスト名がサーバーと表示されているホスト名がサーバーで提供されている場合、サーバーはhandshakeを中止します。
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH  このオプションを設定すると、サーバーはセッションを中止する代わりにSNI応答を送信しません。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
        WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_SNI_SetOptions
*/
void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, unsigned char type,
                                                         unsigned char options);

/*!
    \brief  SSLセッションを使用したSSLオブジェクトのサーバ名指示を使用して、SSLコンテキストから作成されたSSLオブジェクトから作成されます。オプションを以下に説明します。
    \return none  いいえ返します。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param type  どの種類のサーバー名がデータに渡されたかを示します。既知の型は次のとおりです。enum {wolfssl_sni_host_name = 0};
    \param options  選択されたオプションを持つビット単位のセマフォ。利用可能なオプションは次のとおりです。enum {wolfssl_sni_continue_on_mismatch = 0x01、wolfssl_sni_answer_on_mismatch = 0x02};通常、サーバーは、クライアントによって提供されたホスト名がサーバーと表示されているホスト名がサーバーで提供されている場合、サーバーはhandshakeを中止します。
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH  このオプションを設定すると、サーバーはセッションを中止する代わりにSNI応答を送信しません。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
       // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME,
    WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_SetOptions
*/
void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx,
                                     unsigned char type, unsigned char options);

/*!
    \brief  クライアントによってクライアントから提供された名前表示クライアントによって送信されたメッセージセッションを開始する。SNIを取得するためのコンテキストまたはセッション設定が必要ありません。
    \return WOLFSSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  このケースで返されるエラーは、次のいずれかの場合で返されます。バッファはNULL、BUFFERSZ <= 0、SNIはNULL、INOUTSZはNULLまたは<= 0です。
    \return BUFFER_ERROR  不正なクライアントhelloメッセージがあるときにエラーが返されます。
    \return INCOMPLETE_DATA  抽出を完了するのに十分なデータがない場合に返されるエラーです。
    \param buffer  クライアントから提供されたデータへのポインタ（クライアントhello）。
    \param bufferSz  クライアントhelloメッセージのサイズ。
    \param type  どの種類のサーバー名がバッファーから取得されているかを示します。既知の型は次のとおりです。enum {wolfssl_sni_host_name = 0};
    \param sni  出力が保存される場所へのポインタ。

    _Example_
    \code
    unsigned char buffer[1024] = {0};
    unsigned char result[32]   = {0};
    int           length       = 32;
    // read Client Hello to buffer...
    ret = wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer), 0, result, &length));
    if (ret != WOLFSSL_SUCCESS) {
        // sni retrieve failed
    }
    \endcode
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_GetRequest
*/
int wolfSSL_SNI_GetFromBuffer(
                 const unsigned char* clientHello, unsigned int helloSz,
                 unsigned char type, unsigned char* sni, unsigned int* inOutSz);

/*!
    \ingroup IO
    \brief  この関数はSNIオブジェクトのステータスを取得します。
    \return value  SNIがNULLでない場合、この関数はSNI構造体のステータスメンバーのバイト値を返します。
    \return 0  SNIオブジェクトがNULLの場合
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
    …
    Byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = (char*)&type;
    AssertIntEQ(WOLFSSL_SNI_NO_MATCH, wolfSSL_SNI_Status(ssl, type));
    …
    \endcode
    \sa TLSX_SNI_Status
    \sa TLSX_SNI_find
    \sa TLSX_Find
*/
unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type);

/*!
    \brief  SSLセッションでクライアントによって提供されるサーバー名の表示。
    \return size  提供されたSNIデータのサイズ。
    \param ssl  wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param type  どの種類のサーバー名がデータ内で取得されているかを示します。既知の型は次のとおりです。enum {wolfssl_sni_host_name = 0};

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    if (wolfSSL_accept(ssl) == SSL_SUCCESS) {
        void *data = NULL;
        unsigned short size = wolfSSL_SNI_GetRequest(ssl, 0, &data);
    }
    \endcode
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
*/
unsigned short wolfSSL_SNI_GetRequest(WOLFSSL *ssl,
                                               unsigned char type, void** data);

/*!
    \ingroup Setup
    \brief  wolfsslセッションにALPNを設定します。
    \return WOLFSSL_SUCCESS:  成功時に返されます。
    \return BAD_FUNC_ARG  SSLまたはPROTOCOL_NAME_LISTがNULLまたはPROTOCOL_NAME_LISTSZが大きすぎたり、オプションがサポートされていないものを含みます。
    \return MEMORY_ERROR  プロトコルリストのメモリの割り当て中にエラーが発生しました。
    \return SSL_FAILURE  失敗時に返されます。
    \param ssl  使用するWolfSSLセッション。
    \param protocol_name_list  使用するプロトコル名のリスト。カンマ区切り文字列が必要です。
    \param protocol_name_listSz  プロトコル名のリストのサイズ。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    char alpn_list[] = {};

    if (wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
        WOLFSSL_APN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
       // Error setting session ticket
    }
    \endcode
    \sa TLSX_UseALPN
*/
int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
                                unsigned int protocol_name_listSz,
                                unsigned char options);

/*!
    \ingroup TLS
    \brief  この関数は、サーバーによって設定されたプロトコル名を取得します。
    \return SSL_SUCCESS  エラーが投げられていない正常な実行に戻りました。
    \return SSL_FATAL_ERROR  拡張子が見つからなかった場合、またはピアとプロトコルが一致しなかった場合に返されます。2つ以上のプロトコル名が受け入れられている場合は、スローされたエラーもあります。
    \return SSL_ALPN_NOT_FOUND  ピアとプロトコルの一致が見つからなかったことを示す返されました。
    \return BAD_FUNC_ARG  関数に渡されたnull引数があった場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param protocol_name  プロトコル名を表すCHARへのポインタは、ALPN構造に保持されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int err;
    char* protocol_name = NULL;
    Word16 protocol_nameSz = 0;
    err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);

    if(err == SSL_SUCCESS){
	    // Sent ALPN protocol
    }
    \endcode
    \sa TLSX_ALPN_GetRequest
    \sa TLSX_Find
*/
int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name,
                                         unsigned short *size);

/*!
    \ingroup TLS
    \brief  この関数は、alpn_client_listデータをSSLオブジェクトからバッファにコピーします。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。SSLオブジェクトのALPN_CLIENT_LISTメンバーがLISTパラメータにコピーされました。
    \return BAD_FUNC_ARG  listまたはlistszパラメーターがnullの場合に返されます。
    \return BUFFER_ERROR  リストバッファに問題がある場合は（NULLまたはサイズが0の場合）に問題がある場合に返されます。
    \return MEMORY_ERROR  メモリを動的に割り当てる問題がある場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param list  バッファへのポインタ。SSLオブジェクトからのデータがコピーされます。

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #ifdef HAVE_ALPN
    char* list = NULL;
    word16 listSz = 0;
    …
    err = wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz);

    if(err == SSL_SUCCESS){
	    List of protocols names sent by client
    }
    \endcode
    \sa wolfSSL_UseALPN
*/
int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list,
                                             unsigned short *listSz);

/*!
    \brief  'ssl'パラメータに渡されたSSLオブジェクト内の最大フラグメント長。これは、最大フラグメント長拡張機能がWolfSSLクライアントによってClientHelloで送信されることを意味します。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合に返されるエラーです.SSLはNULL、MFLは範囲外です。
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。
    \param ssl  wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseMaxFragment(WOLFSSL* ssl, unsigned char mfl);

/*!
    \brief  SSLコンテキストから作成されたSSLオブジェクトの最大フラグメント長さ 'ctx'パラメータに渡されました。これは、最大フラグメント長拡張機能がWolfSSLクライアントによってClientHelloで送信されることを意味します。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合に返されるエラーです.CTXはNULL、MFLは範囲外です。
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, unsigned char mfl);

/*!
    \brief  'ssl'パラメータに渡されたSSLオブジェクト内のtruncated HMAC。これは、切り捨てられたHMAC拡張機能がWolfSSLクライアントによってClientHelloで送信されることを意味します。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合に返されるエラーです.SSLはNULLです
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseTruncatedHMAC(ssl);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl);

/*!
    \brief  'ctx'パラメータに渡されたSSLコンテキストから作成されたSSLオブジェクトのためのTruncated HMAC。これは、切り捨てられたHMAC拡張機能がWolfSSLクライアントによってClientHelloで送信されることを意味します。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合に返されるエラーです.CTXはNULL
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseTruncatedHMAC(ctx);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx);

/*!
    \brief  OCSPで提示された証明書失効チェックのコストを下げます。
    \return SSL_SUCCESS  tlsx_usecertificateStatusRequestがエラーなしで実行された場合に返されます。
    \return MEMORY_E  メモリの割り当てにエラーがある場合に返されます。
    \return BAD_FUNC_ARG  NULLまたはその他の点では、関数に渡された値が渡される引数がある場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param status_type  tlsx_usecertificateSrequest()に渡され、CertificateStatusRequest構造体に格納されているバイトタイプ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR2_OCSP,
    WOLFSSL_CSR2_OCSP_USE_NONCE) != SSL_SUCCESS){
	    // Failed case.
    }
    \endcode
    \sa TLSX_UseCertificateStatusRequest
    \sa wolfSSL_CTX_UseOCSPStapling
*/
int wolfSSL_UseOCSPStapling(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief
    \return SSL_SUCCESS  関数とサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  未解決の値がサブルーチンに渡された場合、WOLFSSL_CTX構造体がNULLまたはそうでない場合に返されます。
    \return MEMORY_E  関数またはサブルーチンがメモリを正しく割り振ることができなかった場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param status_type  tlsx_usecertificateSrequest()に渡され、CertificateStatusRequest構造体に格納されているバイトタイプ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte statusRequest = 0; // Initialize status request
    …
    switch(statusRequest){
    	case WOLFSSL_CSR_OCSP:
    		if(wolfSSL_CTX_UseOCSPStapling(ssl->ctx, WOLFSSL_CSR_OCSP,
    WOLF_CSR_OCSP_USE_NONCE) != SSL_SUCCESS){
    // UseCertificateStatusRequest failed
    }
    // Continue switch cases
    \endcode
    \sa wolfSSL_UseOCSPStaplingV2
    \sa wolfSSL_UseOCSPStapling
    \sa TLSX_UseCertificateStatusRequest
*/
int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief
    \return SSL_SUCCESS   - 関数とサブルーチンがエラーなしで実行された場合に返されます。
    \return MEMORY_E   - メモリエラーの割り当てがあった場合に返されます。
    \return BAD_FUNC_ARG   -  NULLまたはそれ以外の場合は解読されていない引数が関数またはサブルーチンに渡された場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param status_type  OCSPステータスタイプをロードするバイトタイプ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if (wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP_MULTI, 0) != SSL_SUCCESS){
    	// Did not execute properly. Failure case code block.
    }
    \endcode
    \sa TLSX_UseCertificatStatusRequestV2
    \sa wolfSSL_SNI_SetOptions
    \sa wolfSSL_CTX_SNI_SetOptions
*/
int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief  OCSPステイプルのために。
    \return SSL_SUCCESS  関数とサブルーチンがエラーなしで実行された場合。
    \return BAD_FUNC_ARG  WOLFSSL_CTX構造がnullの場合、または側数変数がクライアント側ではない場合に返されます。
    \return MEMORY_E  メモリの割り当てが失敗した場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param status_type  CertificatStatusRequest構造体にあるバイトタイプで、wolfssl_csr2_ocspまたはwolfssl_csr2_ocsp_multiでなければなりません。

    _Example_
    \code
    WOLFSSL_CTX* ctx  = wolfSSL_CTX_new( protocol method );
    byte status_type;
    byte options;
    ...
    if(wolfSSL_CTX_UseOCSPStaplingV2(ctx, status_type, options); != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode
    \sa TLSX_UseCertificateStatusRequestV2
    \sa wc_RNG_GenerateBlock
    \sa TLSX_Push
*/
int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief  サポートされている楕円曲線拡張子は、 'SSL'パラメータに渡されたSSLオブジェクトでサポートされています。これは、サポートされているカーブがWolfSSLクライアントによってClientHelloで送信されることを意味します。この機能は複数の曲線を有効にするために複数の時間と呼ぶことができます。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合に返されるエラーです.SSLはNULLです。名前は未知の値です。（下記参照）
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。
    \param ssl  wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSupportedCurve
*/
int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name);

/*!
    \brief  サポートされている楕円曲線は、 'ctx'パラメータに渡されたSSLコンテキストから作成されたSSLオブジェクトの拡張子です。これは、サポートされているカーブがWolfSSLクライアントによってClientHelloで送信されることを意味します。この機能は複数の曲線を有効にするために複数の時間と呼ぶことができます。
    \return SSL_SUCCESS  成功時に返されます。
    \return BAD_FUNC_ARG  次のいずれかの場合に返されるエラーです.CTXはNULL、名前は未知の値です。（下記参照）
    \return MEMORY_E  十分なメモリがないときにエラーが返されます。
    \param ctx  wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSupportedCurve
*/
int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           word16 name);

/*!
    \ingroup IO
    \brief  この関数は、供給されたWOLFSSL構造の安全な再交渉を強制します。これはお勧めできません。
    \return SSL_SUCCESS  安全な再ネゴシエーションを正常に設定します。
    \return BAD_FUNC_ARG  sslがNULLの場合、エラーを返します。
    \return MEMORY_E  安全な再交渉のためにメモリを割り当てることができない場合、エラーを返します。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS)
    {
        // Error setting secure renegotiation
    }
    \endcode
    \sa TLSX_Find
    \sa TLSX_UseSecureRenegotiation
*/
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は安全な再交渉ハンドシェイクを実行します。これは、WolfSSLがこの機能を妨げるように強制されます。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  wolfssl構造がnullまたはそうでなければ、許容できない引数がサブルーチンに渡された場合に返されます。
    \return SECURE_RENEGOTIATION_E  ハンドシェイクを再ネゴシエーションすることにエラーが発生した場合に返されます。
    \return SSL_FATAL_ERROR  サーバーまたはクライアント構成にエラーが発生した場合は、再ネゴシエーションが完了できなかった場合に返されます。wolfssl_negotiate()を参照してください。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_Rehandshake(ssl) != SSL_SUCCESS){
	    // There was an error and the rehandshake is not successful.
    }
    \endcode
    \sa wolfSSL_negotiate
    \sa wc_InitSha512
    \sa wc_InitSha384
    \sa wc_InitSha256
    \sa wc_InitSha
    \sa wc_InitMd5
*/
int wolfSSL_Rehandshake(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  セッションチケットを使用するようにWolfSSL構造を強制します。定数hous_session_ticketを定義し、定数NO_WOLFSSL_CLIENTをこの関数を使用するように定義しないでください。
    \return SSL_SUCCESS  セッションチケットを使用したセットに成功しました。
    \return BAD_FUNC_ARG  sslがNULLの場合に返されます。
    \return MEMORY_E  セッションチケットを設定するためのメモリの割り当て中にエラーが発生しました。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSessionTicket(ssl) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode
    \sa TLSX_UseSessionTicket
*/
int wolfSSL_UseSessionTicket(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は、セッションチケットを使用するようにWolfSSLコンテキストを設定します。
    \return SSL_SUCCESS  関数は正常に実行されます。
    \return BAD_FUNC_ARG  CTXがNULLの場合に返されます。
    \return MEMORY_E  内部関数内のメモリの割り当て中にエラーが発生しました。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL_METHOD method = // Some wolfSSL method ;
    ctx = wolfSSL_CTX_new(method);

    if(wolfSSL_CTX_UseSessionTicket(ctx) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode
    \sa TLSX_UseSessionTicket
*/
int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO
    \brief  この機能は、セッション構造のチケットメンバーをバッファにコピーします。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  引数の1つがNULLの場合、またはbufsz引数が0の場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param buf  メモリバッファを表すバイトポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buf;
    word32 bufSz;  // Initialize with buf size
    …
    if(wolfSSL_get_SessionTicket(ssl, buf, bufSz) <= 0){
	    // Nothing was written to the buffer
    } else {
	    // the buffer holds the content from ssl->session->ticket
    }
    \endcode
    \sa wolfSSL_UseSessionTicket
    \sa wolfSSL_set_SessionTicket
*/
int wolfSSL_get_SessionTicket(WOLFSSL* ssl, unsigned char* buf, word32* bufSz);

/*!
    \ingroup IO
    \brief  この関数は、WolfSSL構造体内のwolfssl_session構造体のチケットメンバーを設定します。関数に渡されたバッファはメモリにコピーされます。
    \return SSL_SUCCESS  機能の実行に成功したことに戻ります。関数はエラーなしで返されました。
    \return BAD_FUNC_ARG  WolfSSL構造がNULLの場合に返されます。BUF引数がNULLの場合は、これはスローされますが、bufsz引数はゼロではありません。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param buf  セッション構造のチケットメンバーにロードされるバイトポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buffer; // File to load
    word32 bufSz;
    ...
    if(wolfSSL_KeepArrays(ssl, buffer, bufSz) != SSL_SUCCESS){
    	// There was an error loading the buffer to memory.
    }
    \endcode
    \sa wolfSSL_set_SessionTicket_cb
*/
int wolfSSL_set_SessionTicket(WOLFSSL* ssl, const unsigned char* buf,
                              word32 bufSz);

/*!
    \brief  CallbackSessionTicketは、int（* callbacksessionTicket）（wolfssl *、const unsigned char *、int、void *）の関数ポインタです。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG  WolfSSL構造がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param cb  Type CallbackSessionTicketへの関数ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int sessionTicketCB(WOLFSSL* ssl, const unsigned char* ticket, int ticketSz,
				void* ctx){ … }
    wolfSSL_set_SessionTicket_cb(ssl, sessionTicketCB, (void*)”initial session”);
    \endcode
    \sa wolfSSL_set_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
*/
int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                 CallbackSessionTicket cb, void* ctx);

/*!
    \brief この関数はTLS1.3ハンドシェークが確立したあとでセッションチケットを送信します。

    \return WOLFSSL_SUCCESS セッションチケットが送信された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULL,あるいはTLS v1.3を使用しない場合に返されます。
    \return SIDE_ERROR returned サーバー側でない場合に返されます。
    \return NOT_READY_ERROR ハンドシェークが完了しない場合に返されます。
    \return WOLFSSL_FATAL_ERROR メッセージの生成か送信に失敗した際に返されます。

    \param ssl wolfSSL_new()を使って生成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    ret = wolfSSL_send_SessionTicket(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // New session ticket not sent.
    }
    \endcode

    \sa wolfSSL_get_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
 */
int wolfSSL_send_SessionTicket(WOLFSSL* ssl);

/*!
    \brief  RFC 5077で指定されているセッションチケットをサポートするためのサーバーが。
    \return SSL_SUCCESS  セッションを正常に設定すると返されます。
    \return BAD_FUNC_ARG  失敗した場合に返されます。これは、無効な引数を関数に渡すことによって発生します。
    \param ctx  wolfSSL_CTX_new()で作成されたWOLFSSL_CTXオブジェクトへのポインタ。
    \param cb  セッションチケットを暗号化/復号化するためのユーザーコールバック関数
    \param ssl(Callback)  wolfSSL_new()で作成されたWolfSSLオブジェクトへのポインタ
    \param key_name(Callback)  このチケットコンテキストの一意のキー名はランダムに生成されるべきです
    \param iv(Callback)  ユニークなIVこのチケットの場合、最大128ビット、ランダムに生成されるべきです
    \param mac(Callback)  このチケットの最大256ビットMAC
    \param enc(Callback)  この暗号化パラメータがtrueの場合、ユーザーはキーコード、IV、Macを記入し、チケットを長さのインレルの範囲内に暗号化し、結果として生じる出力長を* outreenに設定する必要があります。 wolfssl_ticket_ret_okを返す暗号化が成功したことをWolfSSLに指示します。この暗号化パラメータがfalseの場合、key_name、iv、およびmacを使用して、リングインレーンの範囲内のチケットの復号化を実行する必要があります。結果の復号長は* outreenに設定する必要があります。 wolfssl_ticket_ret_okを返すと、復号化されたチケットの使用を続行するようにWolfSSLに指示します。 wolfssl_ticket_ret_createを返すと、復号化されたチケットを使用するだけでなく、クライアントに送信するための新しいものを生成するように指示し、最近ロールされている場合に役立つ、フルハンドシェイクを強制したくない。 wolfssl_ticket_ret_rejectを返すと、WolfSSLにこのチケットを拒否し、フルハンドシェイクを実行し、通常のセッション再開のための新しい標準セッションIDを作成します。 wolfssl_ticket_ret_fatalを返すと、致命的なエラーで接続の試みを終了するようにWolfSSLに指示します。
    \param ticket(Callback)  暗号化チケットの入出力バッファ。ENCパラメータを参照してください
    \param inLen(Callback)  チケットパラメータの入力長
    \param outLen(Callback)  チケットパラメータの結果の出力長。コールバックoutlenを入力すると、チケットバッファで使用可能な最大サイズが表示されます。

    _Example_
    \code
    See wolfssl/test.h myTicketEncCb() used by the example
    server and example echoserver.
    \endcode
    \sa wolfSSL_CTX_set_TicketHint
    \sa wolfSSL_CTX_set_TicketEncCtx
*/
int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb);

/*!
    \brief  サーバーサイドの使用のために。
    \return SSL_SUCCESS  セッションを正常に設定すると返されます。
    \return BAD_FUNC_ARG  失敗した場合に返されます。これは、無効な引数を関数に渡すことによって発生します。
    \param ctx  wolfSSL_CTX_new()で作成されたWOLFSSL_CTXオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_set_TicketEncCb
*/
int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int);

/*!
    \brief  折り返し電話。サーバーサイドの使用のために。
    \return SSL_SUCCESS  セッションを正常に設定すると返されます。
    \return BAD_FUNC_ARG  失敗した場合に返されます。これは、無効な引数を関数に渡すことによって発生します。
    \param ctx  wolfSSL_CTX_new()で作成されたWOLFSSL_CTXオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_set_TicketEncCb
*/
int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void*);

/*!
    \brief  折り返し電話。サーバーサイドの使用のために。
    \return userCtx  セッションを正常に取得すると返されます。
    \return NULL  失敗した場合に返されます。これは、無効な引数を関数に渡すことによって、またはユーザーコンテキストが設定されていないときに発生します。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_CTX_set_TicketEncCtx
*/
void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx);

/*!
    \brief  この機能には、WolfSSL構造のHSDonectxメンバーが設定されています。
    \return SSL_SUCCESS  関数がエラーなしで実行された場合に返されます。WolfSSL構造体のHSDONECBとHSDonectxメンバーが設定されています。
    \return BAD_FUNC_ARG  wolfssl構造体がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。
    \param cb  int（* HandshakedOneCB）（wolfssl *、void *）の署名を持つタイプHandshakedOneCBの関数ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int myHsDoneCb(WOLFSSL* ssl, void* user_ctx){
        // callback function
    }
    …
    wolfSSL_SetHsDoneCb(ssl, myHsDoneCb, NULL);
    \endcode
    \sa HandShakeDoneCb
*/
int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx);

/*!
    \ingroup IO
    \brief  この関数はセッションから統計を印刷します。
    \return SSL_SUCCESS  関数とサブルーチンがエラーなしで戻った場合に返されます。セッション統計は正常に取得され印刷されました。
    \return BAD_FUNC_ARG  サブルーチンwolfssl_get_session_stats()が許容できない引数に渡された場合に返されます。
    \return BAD_MUTEX_E  サブルーチンにミューテックスエラーがあった場合に返されます。

    _Example_
    \code
    // You will need to have a session object to retrieve stats from.
    if(wolfSSL_PrintSessionStats(void) != SSL_SUCCESS	){
        // Did not print session stats
    }

    \endcode
    \sa wolfSSL_get_session_stats
*/
int wolfSSL_PrintSessionStats(void);

/*!
    \ingroup IO
    \brief  この関数はセッションの統計を取得します。
    \return SSL_SUCCESS  関数とサブルーチンがエラーなしで戻った場合に返されます。セッション統計は正常に取得され印刷されました。
    \return BAD_FUNC_ARG  サブルーチンwolfssl_get_session_stats()が許容できない引数に渡された場合に返されます。
    \return BAD_MUTEX_E  サブルーチンにミューテックスエラーがあった場合に返されます。
    \param active  現在のセッションの合計を表すWord32ポインタ。
    \param total  総セッションを表すWord32ポインタ。
    \param peak  ピークセッションを表すWord32ポインタ。

    _Example_
    \code
    int wolfSSL_PrintSessionStats(void){
    …
    ret = wolfSSL_get_session_stats(&totalSessionsNow,
    &totalSessionsSeen, &peak, &maxSessions);
    …
    return ret;
    \endcode
    \sa wolfSSL_PrintSessionStats
*/
int wolfSSL_get_session_stats(unsigned int* active,
                                          unsigned int* total,
                                          unsigned int* peak,
                                          unsigned int* maxSessions);

/*!
    \ingroup TLS
    \brief  この関数はCRとSRの値をコピーしてからWC_PRF（疑似ランダム関数）に渡し、その値を返します。
    \return 0  成功した
    \return BUFFER_E  バッファのサイズにエラーが発生した場合に返されます。
    \return MEMORY_E  サブルーチンが動的メモリを割り当てることができなかった場合に返されます。
    \param ms  マスターシークレットはアレイ構造に保持されています。
    \param msLen  マスターシークレットの長さ。
    \param pms  マスター前の秘密はアレイ構造に保持されています。
    \param pmsLen  マスタープレマスターシークレットの長さ。
    \param cr  クライアントのランダム
    \param sr  サーバーのランダムです。
    \param tls1_2  バージョンが少なくともTLSバージョン1.2であることを意味します。

    _Example_
    \code
    WOLFSSL* ssl;

    called in MakeTlsMasterSecret and retrieves the necessary
    information as follows:

    int MakeTlsMasterSecret(WOLFSSL* ssl){
	int ret;
	ret = wolfSSL_makeTlsMasterSecret(ssl->arrays->masterSecret, SECRET_LEN,
    ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
    ssl->arrays->clientRandom, ssl->arrays->serverRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    return ret;

    }
    \endcode
    \sa wc_PRF
    \sa MakeTlsMasterSecret
*/

int wolfSSL_MakeTlsMasterSecret(unsigned char* ms, word32 msLen,
                               const unsigned char* pms, word32 pmsLen,
                               const unsigned char* cr, const unsigned char* sr,
                               int tls1_2, int hash_type);

/*!
    \ingroup CertsKeys
    \brief  TLSキーを導き出すための外部のラッパー。
    \return 0  成功に戻りました。
    \return BUFFER_E  LABLENとSEADLENの合計（合計サイズを計算）が最大サイズを超えると返されます。
    \return MEMORY_E  メモリの割り当てが失敗した場合に返されます。
    \param key_data  DeriveTlSkeysに割り当てられ、最終ハッシュを保持するためにWC_PRFに渡されたバイトポインタ。
    \param keyLen  WOLFSSL構造体のスペックメンバーからのDerivetlskeysで派生したWord32タイプ。
    \param ms  WolfSSL構造内でアレイ構造に保持されているマスターシークレットを保持する定数ポインタ型。
    \param msLen  列挙された定義で、マスターシークレットの長さを保持するWord32タイプ。
    \param sr  WOLFSSL構造内の配列構造のServerRandomメンバーへの定数バイトポインタ。
    \param cr  WolfSSL構造内の配列構造のClientRandomメンバーへの定数バイトポインタ。
    \param tls1_2  ISATLEASTLSV1_2()から返された整数型。

    _Example_
    \code
    int DeriveTlsKeys(WOLFSSL* ssl){
    int ret;
    …
    ret = wolfSSL_DeriveTlsKeys(key_data, length, ssl->arrays->masterSecret,
    SECRET_LEN, ssl->arrays->clientRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    }
    \endcode
    \sa wc_PRF
    \sa DeriveTlsKeys
    \sa IsAtLeastTLSv1_2
*/

int wolfSSL_DeriveTlsKeys(unsigned char* key_data, word32 keyLen,
                               const unsigned char* ms, word32 msLen,
                               const unsigned char* sr, const unsigned char* cr,
                               int tls1_2, int hash_type);

/*!
    \brief  ハンドシェイクコールバックが設定されます。これは、デバッガが利用できず、スニッフィングが実用的ではない場合に、サポートをデバッグするための組み込みシステムで役立ちます。ハンドシェイクエラーが発生したか否かが呼び出されます。SSLパケットの最大数が既知であるため、動的メモリは使用されません。パケット名をPacketNames []でアクセスできます。接続拡張機能は、タイムアウト値とともにタイムアウトコールバックを設定することもできます。これは、ユーザーがTCPスタックをタイムアウトするのを待ったくない場合に便利です。この拡張子は、コールバックのどちらか、またはどちらのコールバックも呼び出されません。
    \return SSL_SUCCESS  成功時に返されます。
    \return GETTIME_ERROR  gettimeofday()がエラーを検出した場合、返されます。
    \return SETITIMER_ERROR  setItimer()がエラーを検出した場合、返されます。
    \return SIGACT_ERROR  sigAction()がエラーを検出した場合、返されます。
    \return SSL_FATAL_ERROR  基になるssl_connect()呼び出しがエラーを検出した場合に返されます。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_accept_ex
*/
int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                       TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

/*!
    \brief  設定する。これは、デバッガが利用できず、スニッフィングが実用的ではない場合に、サポートをデバッグするための組み込みシステムで役立ちます。ハンドシェイクエラーが発生したか否かが呼び出されます。SSLパケットの最大数が既知であるため、動的メモリは使用されません。パケット名をPacketNames []でアクセスできます。接続拡張機能は、タイムアウト値とともにタイムアウトコールバックを設定することもできます。これは、ユーザーがTCPスタックをタイムアウトするのを待ったくない場合に便利です。この拡張子は、コールバックのどちらか、またはどちらのコールバックも呼び出されません。
    \return SSL_SUCCESS  成功時に返されます。
    \return GETTIME_ERROR  gettimeofday()がエラーを検出した場合、返されます。
    \return SETITIMER_ERROR  setItimer()がエラーを検出した場合、返されます。
    \return SIGACT_ERROR  sigAction()がエラーを検出した場合、返されます。
    \return SSL_FATAL_ERROR  基礎となるssl_accept()呼び出しがエラーを検出した場合に返されます。

    _Example_
    \code
    none
    \endcode
    \sa wolfSSL_connect_ex
*/
int wolfSSL_accept_ex(WOLFSSL* ssl, HandShakeCallBacki hsCb,
                      TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

/*!
    \ingroup IO
    \brief  これはBIOの内部ファイルポインタを設定するために使用されます。
    \return SSL_SUCCESS  ファイルポインタを正常に設定します。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \param bio  ペアを設定するためのWOLFSSL_BIO構造体。
    \param fp  バイオで設定するファイルポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, fp, BIO_CLOSE);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_get_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c);

/*!
    \ingroup IO
\brief  この関数は、    \brief  これは、BIOの内部ファイルポインタを取得するために使用されます。
    \return SSL_SUCCESS  ファイルポインタを正常に取得します。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \param bio  ペアを設定するためのWOLFSSL_BIO構造体。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_get_fp(bio, &fp);
    // check ret value
    \endcode
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp);

/*!
    \ingroup Setup
    \brief  この関数は、秘密鍵が使用されている証明書との一致であることを確認します。
    \return SSL_SUCCESS  うまく一致します。
    \return SSL_FAILURE  エラーケースに遭遇した場合
    \return <0  ssl_failure以外のすべてのエラーケースは負の値です。

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create and set up ssl
    ret  = wolfSSL_check_private_key(ssl);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_check_private_key(const WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief  この機能は、渡されたNID値に一致する拡張索引を探して返します。
    \return >=  0拡張インデックスが成功した場合に返されます。
    \return -1  拡張が見つからないかエラーが発生した場合
    \param x509  拡張のために解析する証明書。
    \param nid  見つかる拡張OID。

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int lastPos = -1;
    int idx;

    idx = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints, lastPos);
    \endcode
*/
int wolfSSL_X509_get_ext_by_NID(const WOLFSSL_X509* x509,
                                             int nid, int lastPos);

/*!
    \ingroup CertsKeys
    \brief  この関数は、渡されたNID値に合った拡張子を探して返します。
    \return pointer  STACK_OF（wolfssl_asn1_object）ポインタが成功した場合に返されます。
    \return NULL  拡張が見つからないかエラーが発生した場合
    \param x509  拡張のために解析する証明書。
    \param nid  見つかる拡張OID。
    \param c  not nullが複数の拡張子に-2に設定されていない場合は-1が見つかりませんでした。

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int c;
    int idx = 0;
    STACK_OF(WOLFSSL_ASN1_OBJECT)* sk;

    sk = wolfSSL_X509_get_ext_d2i(x509, NID_basic_constraints, &c, &idx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode
    \sa wolfSSL_sk_ASN1_OBJECT_free
*/
void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509,
                                                     int nid, int* c, int* idx);

/*!
    \ingroup CertsKeys
    \brief  この関数はDER証明書のハッシュを返します。
    \return SSL_SUCCESS  ハッシュの作成に成功しました。
    \return SSL_FAILURE  不良入力または失敗したハッシュに戻りました。
    \param x509  ハッシュを得るための証明書。
    \param digest  使用するハッシュアルゴリズム
    \param buf  ハッシュを保持するためのバッファ。

    _Example_
    \code
    WOLFSSL_X509* x509;
    unsigned char buffer[64];
    unsigned int bufferSz;
    int ret;

    ret = wolfSSL_X509_digest(x509, wolfSSL_EVP_sha256(), buffer, &bufferSz);
    //check ret value
    \endcode
    \sa none
*/
int wolfSSL_X509_digest(const WOLFSSL_X509* x509,
        const WOLFSSL_EVP_MD* digest, unsigned char* buf, unsigned int* len);

/*!
    \ingroup Setup
    \brief  ハンドシェイク中に使用するために、WolfSSL構造の証明書を設定するために使用されます。
    \return SSL_SUCCESS  設定の成功した引数について。
    \return SSL_FAILURE  NULL引数が渡された場合。
    \param ssl  証明書を設定するためのWolfSSL構造。

    _Example_
    \code WOLFSSL* ssl;
    WOLFSSL_X509* x509
    int ret;
    // create ssl object and x509
    ret  = wolfSSL_use_certificate(ssl, x509);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup Setup
    \biiこfは、この関数は、handshakeの間に使用するためにWolfSSL構造の証明書を設定するために使用されます。DERフォーマットバッファが予想されます。
    \return SSL_SUCCESS  設定の成功した引数について。
    \return SSL_FAILURE  NULL引数が渡された場合。
    \param ssl  証明書を設定するためのWolfSSL構造。
    \param der  使用する証明書。

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* der;
    int derSz;
    int ret;
    // create ssl object and set DER variables
    ret  = wolfSSL_use_certificate_ASN1(ssl, der, derSz);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                     int derSz);

/*!
    \ingroup CertsKeys
    \brief  これはWolfSSL構造の秘密鍵を設定するために使用されます。
    \return SSL_SUCCESS  設定の成功した引数について。
    \return SSL_FAILURE  NULL SSLが渡された場合。すべてのエラーケースは負の値になります。
    \param ssl  引数を設定するためのWolfSSL構造。

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_EVP_PKEY* pkey;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey(ssl, pkey);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_PrivateKey(WOLFSSL* ssl, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys
    \brief  これはWolfSSL構造の秘密鍵を設定するために使用されます。DERフォーマットのキーバッファが予想されます。
    \return SSL_SUCCESS  秘密鍵の構文解析と設定に成功した場合。
    \return SSL_FAILURE  NULL SSLが渡された場合。すべてのエラーケースは負の値になります。
    \param pri  秘密鍵の種類。
    \param ssl  引数を設定するためのWolfSSL構造。
    \param der  バッファー保持DERキー。

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey_ASN1(1, ssl, pkey, pkeySz);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_PrivateKey_ASN1(int pri, WOLFSSL* ssl,
                                            unsigned char* der, long derSz);

/*!
    \ingroup CertsKeys
    \brief  これはWolfSSL構造の秘密鍵を設定するために使用されます。DERフォーマットのRSAキーバッファが予想されます。
    \return SSL_SUCCESS  秘密鍵の構文解析と設定に成功した場合。
    \return SSL_FAILURE  NULL SSLが渡された場合。すべてのエラーケースは負の値になります。
    \param ssl  引数を設定するためのWolfSSL構造。
    \param der  バッファー保持DERキー。

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up RSA private key
    ret  = wolfSSL_use_RSAPrivateKey_ASN1(ssl, pkey, pkeySz);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_RSAPrivateKey_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                long derSz);

/*!
    \ingroup CertsKeys
    \brief  この関数は、DSAのパラメータを新しく作成されたWOLFSSL_DH構造体に重複しています。
    \return WOLFSSL_DH  重複した場合はWolfSSL_DH構造体を返す場合
    \return NULL  失敗すると

    _Example_
    \code
    WOLFSSL_DH* dh;
    WOLFSSL_DSA* dsa;
    // set up dsa
    dh = wolfSSL_DSA_dup_DH(dsa);

    // check dh is not null
    \endcode
    \sa none
*/
WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *r);

/*!
    \ingroup Setup
    \brief  これはハンドシェイクを完了した後にマスターキーを取得するために使用されます。
    \return >0  データの取得に成功した場合、0より大きい値を返します。
    \return 0  ランダムなデータバッファまたはエラー状態が返されない場合は0
    \return max  渡されたOUTSZが0の場合、必要な最大バッファサイズが返されます。
    \param ses  マスターシークレットバッファを取得するためのWolfSSL_SESSION構造。
    \param out  データを保持するためのバッファ。

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret(ses, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_SESSION_get_master_secret(ses, buffer, bufferSz);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key(const WOLFSSL_SESSION* ses,
        unsigned char* out, int outSz);

/*!
    \ingroup Setup
    \brief  これはマスター秘密鍵の長さを取得するために使用されます。
    \return size  マスターシークレットキーサイズを返します。

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret_length(ses);
    buffer = malloc(bufferSz);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key_length(const WOLFSSL_SESSION* ses);

/*!
    \ingroup Setup
    \bri f  この関数は、れは、CTXのWOLFSSL_X509_STORE構造の設定機能です。
    \return none  返品不可。
    \param ctx  Cert Storeポインタを設定するためのWolfSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx and st
    st = wolfSSL_CTX_set_cert_store(ctx, st);
    //use st
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);

/*!
    \ingroup CertsKeys
    \brief  この関数はBIOからDERバッファを取得し、それをWolfSSL_X509構造に変換します。
    \return pointer  成功したwolfssl_x509構造ポインタを返します。
    \return Null  失敗時にNULLを返します
    \param bio  DER証明書バッファを持つWOLFSSL_BIO構造体体へのポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // load DER into bio
    x509 = wolfSSL_d2i_X509_bio(bio, NULL);
    Or
    wolfSSL_d2i_X509_bio(bio, &x509);
    // use x509 returned (check for NULL)
    \endcode
    \sa none
*/
WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509** x509);

/*!
    \ingroup Setup
    \bri f  この関数は、れは、CTXのWOLFSSL_X509_STORE構造のゲッター関数です。
    \return WOLFSSL_X509_STORE*  ポインタを正常に入手します。
    \return NULL  NULL引数が渡された場合に返されます。

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx
    st = wolfSSL_CTX_get_cert_store(ctx);
    //use st
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_cert_store
*/
WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO
    \brief  保留中のバイト数を読み取る数を取得します。BIOタイプがBIO_BIOの場合、ペアから読み取る番号です。BIOにSSLオブジェクトが含まれている場合は、SSLオブジェクトからのデータを保留中です（WolfSSL_Pending（SSL））。bio_memoryタイプがある場合は、メモリバッファのサイズを返します。
    \return >=0  保留中のバイト数。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int pending;
    bio = wolfSSL_BIO_new();
    …
    pending = wolfSSL_BIO_ctrl_pending(bio);
    \endcode
    \sa wolfSSL_BIO_make_bio_pair
    \sa wolfSSL_BIO_new
*/
size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *b);

/*!
    \ingroup Setup
    \biiefは、この関数は、ハンドシェイク中にサーバーによって送信されたランダムなデータを取得するために使用されます。
    \return >0  データの取得に成功した場合、0より大きい値を返します。
    \return 0  ランダムなデータバッファまたはエラー状態が返されない場合は0
    \return max  渡されたOUTSZが0の場合、必要な最大バッファサイズが返されます。
    \param ssl  クライアントのランダムデータバッファを取得するためのWolfSSL構造。
    \param out  ランダムデータを保持するためのバッファ。

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_server_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_server_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_server_random(const WOLFSSL *ssl,
                                             unsigned char *out, size_t outlen);

/*!
    \ingroup Setup
    \biiefは、この関数は、ハンドシェイク中にクライアントによって送信されたランダムなデータを取得するために使用されます。
    \return >0  データの取得に成功した場合、0より大きい値を返します。
    \return 0  ランダムなデータバッファまたはエラー状態が返されない場合は0
    \return max  渡されたOUTSZが0の場合、必要な最大バッファサイズが返されます。
    \param ssl  クライアントのランダムデータバッファを取得するためのWolfSSL構造。
    \param out  ランダムデータを保持するためのバッファ。

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_client_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_client_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_client_random(const WOLFSSL* ssl,
                                              unsigned char* out, size_t outSz);

/*!
    \ingroup Setup
    \brief  これはCTXで設定されたパスワードコールバックのゲッター関数です。
    \return func  成功すると、コールバック関数を返します。
    \return NULL  CTXがNULLの場合、NULLが返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    wc_pem_password_cb cb;
    // setup ctx
    cb = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use cb
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX*
                                                                  ctx);

/*!
    \ingroup Setup
    \bri f  この関数は、れは、CTXで設定されているパスワードコールバックユーザーデータの取得機能です。
    \return pointer  成功すると、ユーザーデータポインタを返します。
    \return NULL  CTXがNULLの場合、NULLが返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    // setup ctx
    data = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use data
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void *wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx);

/*!
    \ingroup CertsKeys
    \brief  この関数はwolfssl_pem_read_bio_x509と同じように動作します。AUXは、信頼できる/拒否されたユースケースや人間の読みやすさのためのフレンドリーな名前などの追加情報を含むことを意味します。
    \return WOLFSSL_X509  PEMバッファの解析に成功した場合、wolfssl_x509構造が返されます。
    \return Null  PEMバッファの解析に失敗した場合。
    \param bp  WOLFSSL_BIO構造体体からPEMバッファを取得します。
    \param x  wolfssl_x509を機能副作用で設定する場合
    \param cb  パスワードコールバック

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // setup bio
    X509 = wolfSSL_PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    //check x509 is not null and then use it
    \endcode
    \sa wolfSSL_PEM_read_bio_X509
*/
WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_AUX
        (WOLFSSL_BIO *bp, WOLFSSL_X509 **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup CertsKeys
    \brief  WOLFSSL_CTX構造体のDHメンバーをdiffie-hellmanパラメータで初期化します。
    \return SSL_SUCCESS  関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG  CTXまたはDH構造体がNULLの場合に返されます。
    \return SSL_FATAL_ERROR  構造値を設定するエラーが発生した場合に返されます。
    \return MEMORY_E  メモリを割り当てることができなかった場合に返されます。
    \param ctx  wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL_DH* dh;
    …
    return wolfSSL_CTX_set_tmp_dh(ctx, dh);
    \endcode
    \sa wolfSSL_BN_bn2bin
*/
long wolfSSL_CTX_set_tmp_dh(WOLFSSL_CTX* ctx, WOLFSSL_DH* dh);

/*!
    \ingroup CertsKeys
    \brief  この関数は、BIOのPEMバッファからDSAパラメータを取得します。
    \return WOLFSSL_DSA  PEMバッファの解析に成功した場合、WolfSSL_DSA構造が作成され、返されます。
    \return Null  PEMバッファの解析に失敗した場合。
    \param bio  PEMメモリポインタを取得するためのWOLFSSL_BIO構造体体へのポインタ。
    \param x  新しいWolfSSL_DSA構造に設定するポインタ。
    \param cb  パスワードコールバック関数

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_DSA* dsa;
    // setup bio
    dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL);

    // check dsa is not NULL and then use dsa
    \endcode
    \sa none
*/
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp,
    WOLFSSL_DSA **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup Debug
    \brief  この関数は、wolfssl_Errorに遭遇した最後のエラーの絶対値を返します。
    \return error  最後のエラーの絶対値を返します。

    _Example_
    \code
    unsigned long err;
    ...
    err = wolfSSL_ERR_peek_last_error();
    // inspect err value
    \endcode
    \sa wolfSSL_ERR_print_errors_fp
*/
unsigned long wolfSSL_ERR_peek_last_error(void);

/*!
    \ingroup CertsKeys
    \brief  この関数はピアの証明書チェーンを取得します。
    \return pointer  ピアの証明書スタックへのポインタを返します。
    \return NULL  ピア証明書がない場合に返されます。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    wolfSSL_connect(ssl);
    STACK_OF(WOLFSSL_X509)* chain = wolfSSL_get_peer_cert_chain(ssl);
    ifchain){
	    // You have a pointer to the peer certificate chain
    }
    \endcode
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL*);

/*!
    \ingroup Setup
    \brief  この関数は、WOLFSSL_CTXオブジェクトのオプションビットをリセットします。
    \return option  新しいオプションビット

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1);
    \endcode
    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_CTX_clear_options(WOLFSSL_CTX* ctx, long opt);

/*!
    \ingroup IO
    \brief  この関数は、WolfSSL構造のjobjectrefメンバーを設定します。
    \return SSL_SUCCESS  jobjectrefがobjptrに正しく設定されている場合に返されます。
    \return SSL_FAILURE  関数が正しく実行されず、jobjectrefが設定されていない場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new();
    void* objPtr = &obj;
    ...
    if(wolfSSL_set_jobject(ssl, objPtr)){
    	// The success case
    }
    \endcode
    \sa wolfSSL_get_jobject
*/
int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr);

/*!
    \ingroup IO
    \brief  この関数は、wolfssl構造のjobjectrefメンバーを返します。
    \return value  wolfssl構造体がnullでない場合、関数はjobjectref値を返します。
    \return NULL  wolfssl構造体がNULLの場合に返されます。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL(ctx);
    ...
    void* jobject = wolfSSL_get_jobject(ssl);

    if(jobject != NULL){
    	// Success case
    }
    \endcode
    \sa wolfSSL_set_jobject
*/
void* wolfSSL_get_jobject(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数はSSL内のコールバックを設定します。コールバックはハンドシェイクメッセージを観察することです。CBのNULL値はコールバックをリセットします。
    \return SSL_SUCCESS  成功しています。
    \return SSL_FAILURE  NULL SSLが渡された場合。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    \endcode
    \sa wolfSSL_set_msg_callback_arg
*/
int wolfSSL_set_msg_callback(WOLFSSL *ssl, SSL_Msg_Cb cb);

/*!
    \ingroup Setup
    \brief  この関数は、SSL内の関連コールバックコンテキスト値を設定します。値はコールバック引数に渡されます。
    \return none  返品不可。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    wolfSSL_set_msg_callback(ssl, arg);
    \endcode
    \sa wolfSSL_set_msg_callback
*/
int wolfSSL_set_msg_callback_arg(WOLFSSL *ssl, void* arg);

/*!
    \ingroup CertsKeys
    \brief  この関数は、存在する場合は、ピア証明書からaltnameを返します。
    \return NULL  次のAltNameがない場合。
    \return cert->altNamesNext->name  wolfssl_x509から、AltNameリストからの文字列値である構造が存在する場合に返されます。

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
                                                        DYNAMIC_TYPE_X509);
    …
    int x509NextAltName = wolfSSL_X509_get_next_altname(x509);
    if(x509NextAltName == NULL){
            //There isn’t another alt name
    }
    \endcode
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
char* wolfSSL_X509_get_next_altname(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief  関数は、x509がnullのかどうかを確認し、そうでない場合は、WOLFSSL_X509構造体のNotBeforeメンバーを返します。
    \return pointer  WOLFSSL_ASN1_TIMEへのポインタ（WOLFSSL_X509構造体のNotBeforeメンバーへのポインタ）を返します。
    \return NULL  WOLFSSL_X509構造体がNULLの場合に返されます。
    \param x509 WOLFSSL_X509構造体へのポインタ

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    …
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notBefore(x509);
    if(notAfter == NULL){
            //The x509 object was NULL
    }
    \endcode
    \sa wolfSSL_X509_get_notAfter
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(WOLFSSL_X509* x509);

/*!
    \ingroup IO
    \brief  この関数はクライアント側で呼び出され、サーバーとのSSL/TLSハンドシェイクを開始します。
    この関数が呼び出されるまでに下層の通信チャネルはすでに設定されている必要があります。
    wolfSSL_connect()は、ブロッキングとノンブロッキングI/Oの両方で動作します。
    下層のI/Oがノンブロッキングの場合、wolfSSL_connect()は、下層のI/OがwolfSSL_connectの要求（送信データ、受信データ）を満たすことができなかったときには即戻ります。
    この場合、wolfSSL_get_error()の呼び出しでSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかが返されます。
    呼び出したプロセスは、下層のI/OががREADYになった時点で、WOLFSSLが停止したときから再開できるようにwolfSSL_connect()への呼び出しを繰り返す必要があります。
    これにはselect()を使用して必要な条件が整ったかどうかを確認できます。
    ブロッキングI/Oを使用する場合は、ハンドシェークが終了するかエラーが発生するまで戻ってきません。
    wolfSSLはOpenSSLと比べて証明書検証に異なるアプローチを取ります。クライアントのデフォルトポリシーはサーバーを認証することです。
    これは、CA証明書を読み込まない場合、サーバーを確認することができず”-155”のエラーコードが返されます。
    OpenSSLと同じ振る舞い（つまり、CA証明書のロードなしでサーバー認証を成功させる）を取らせたい場合には、セキュリティ面でお勧めはしませんが、
    SSL_CTX_SET_VERIFY（ctx、SSL_VERIFY_NONE、0)を呼び出すことで可能となります。

    \return SSL_SUCCESS  成功した場合に返されます。
    \return SSL_FATAL_ERROR  エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出します。
    \param ssl  wolfSSL_new()を使用して作成されたWolfSSL構造へのポインタ。

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
    err = wolfSSL_get_error(ssl, ret);
    printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_accept
*/
int  wolfSSL_connect(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数はサーバー側で呼び出されて、HellORetryRequestメッセージにCookieを含める必要があることを示します。Cookieは現在のトランスクリプトのハッシュを保持しているので、別のサーバープロセスは応答でClientHelloを処理できます。秘密はCookieデータの整合性チェックをGenertingするときに使用されます。
    \param [in,out]    ssl l wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in]  秘密を保持しているバッファへのポインタを秘密にします。渡すNULLは、新しいランダムシークレットを生成することを示します。
    \param [in]  シークスのサイズをバイト単位でサイズ。0を渡すと、デフォルトのサイズを使用することを示します.WC_SHA256_DIGEST_SIZE（またはSHA-256が使用できない場合はWC_SHA_DIGEST_SIZE）。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  クライアントで呼び出された場合。
    \return WOLFSSL_SUCCESS  成功した場合に返されます。
    \return MEMORY_ERROR  秘密を保存するために動的メモリを割り当てる場合に失敗しました。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    char secret[32];
    ...
    ret = wolfSSL__send_hrr_cookie(ssl, secret, sizeof(secret));
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set use of Cookie and secret
    }
    \endcode
    \sa wolfSSL_new
*/
int  wolfSSL_send_hrr_cookie(WOLFSSL* ssl,
    const unsigned char* secret, unsigned int secretSz);

/*!

    \ingroup Setup

    \brief この関数はサーバー側で呼び出され、HelloRetryRequestメッセージがクッキーを含んではならないこと、
    DTLSv1.3が使用されている場合にはクッキーの交換がハンドシェークに含まれないことを表明します。
    DTLSv1.3ではクッキー交換を行わないとサーバーがDoS/Amplification攻撃を受けやすくなる可能性があることに留意してください。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return WOLFSSL_SUCCESS 成功時に返されます。
    \return BAD_FUNC_ARG sslがNULLあるいはTLS v1.3を使用していない場合に返されます。
    \return SIDE_ERROR クライアント側でこの関数が呼び出された場合に返されます。

    \sa wolfSSL_send_hrr_cookie
*/
int wolfSSL_disable_hrr_cookie(WOLFSSL* ssl);


/*!
    \ingroup Setup
    \brief  この関数はサーバー上で呼び出され、ハンドシェイク完了時にセッション再開のためのセッションチケットの送信を行わないようにします。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \return BAD_FUNC_ARG  CTXがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  クライアントで呼び出された場合。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_ticket_TLSv13(ctx);
    if (ret != 0) {
        // failed to set no ticket
    }
    \endcode
    \sa wolfSSL_no_ticket_TLSv13
*/
int  wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief  ハンドシェイクが完了すると、この関数はサーバー上で再開セッションチケットの送信を停止するように呼び出されます。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  クライアントで呼び出された場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_ticket_TLSv13(ssl);
    if (ret != 0) {
        // failed to set no ticket
    }
    \endcode
    \sa wolfSSL_CTX_no_ticket_TLSv13
*/
int  wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は、Authenticationにプリシェアキーを使用している場合、DIFFIE-HELLMAN（DH）スタイルのキー交換を許可するTLS V1.3 WolfSSLコンテキストで呼び出されます。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \return BAD_FUNC_ARG  CTXがNULLの場合、またはTLS v1.3を使用していない場合。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_dhe_psk(ctx);
    if (ret != 0) {
        // failed to set no DHE for PSK handshakes
    }
    \endcode
    \sa wolfSSL_no_dhe_psk
*/
int  wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief  この関数は、事前共有鍵を使用しているTLS V1.3クライアントまたはサーバーで、にDiffie-Hellman（DH）スタイルの鍵交換を許可しないように設定します。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_dhe_psk(ssl);
    if (ret != 0) {
        // failed to set no DHE for PSK handshakes
    }
    \endcode
    \sa wolfSSL_CTX_no_dhe_psk
*/
int  wolfSSL_no_dhe_psk(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は、TLS v1.3クライアントまたはサーバーのwolfsslで呼び出されて、キーのロールオーバーを強制します。KeyUpdateメッセージがピアに送信され、新しいキーが暗号化のために計算されます。ピアはKeyUpdateメッセージを送り、新しい復号化キーWILを計算します。この機能は、ハンドシェイクが完了した後にのみ呼び出すことができます。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return WANT_WRITE  書き込みが準備ができていない場合

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_update_keys(ssl);
    if (ret == WANT_WRITE) {
        // need to call again when I/O ready
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // failed to send key update
    }
    \endcode
    \sa wolfSSL_write
*/
int  wolfSSL_update_keys(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は、TLS v1.3クライアントまたはサーバーのwolfsslで呼び出され、キーのロールオーバーが進行中かどうかを判断します。wolfssl_update_keys()が呼び出されると、KeyUpdateメッセージが送信され、暗号化キーが更新されます。復号化キーは、応答が受信されたときに更新されます。
    \param [in]  ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [out]  キー更新応答が必要ない場合は必須0。1キー更新応答が必要ない場合。
    \return 0  成功した。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int required;
    ...
    ret = wolfSSL_key_update_response(ssl, &required);
    if (ret != 0) {
        // bad parameters
    }
    if (required) {
        // encrypt Key updated, awaiting response to change decrypt key
    }
    \endcode
    \sa wolfSSL_update_keys
*/
int  wolfSSL_key_update_response(WOLFSSL* ssl, int* required);

/*!
    \ingroup Setup
    \brief  この関数は、TLS v1.3クライアントのWolfSSLコンテキストで呼び出され、クライアントはサーバーからの要求に応じてPost Handshakeを送信できるようにします。これは、クライアント認証などを必要としないページを持つWebサーバーに接続するときに役立ちます。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \return BAD_FUNC_ARG  CTXがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  サーバーで呼び出された場合。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ctx);
    if (ret != 0) {
        // failed to allow post handshake authentication
    }
    \endcode
    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_CTX_allow_post_handshake_auth(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief  この関数は、TLS V1.3クライアントWolfSSLで呼び出され、クライアントはサーバーからの要求に応じてハンドシェイクを送ります。handshakeクライアント認証拡張機能はClientHelloで送信されます。これは、クライアント認証などを必要としないページを持つWebサーバーに接続するときに役立ちます。
    \param [in,out]  ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  サーバーで呼び出された場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ssl);
    if (ret != 0) {
        // failed to allow post handshake authentication
    }
    \endcode
    \sa wolfSSL_CTX_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_allow_post_handshake_auth(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数は、TLS v1.3クライアントからクライアント証明書を要求します。これは、Webサーバーがクライアント認証やその他のものを必要とするページにサービスを提供している場合に役立ちます。接続で最大256の要求を送信できます。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return WANT_WRITE  書き込みが準備ができていない場合
    \return SIDE_ERROR  クライアントで呼び出された場合。
    \return NOT_READY_ERROR  ハンドシェイクが終了していないときに呼び出された場合。
    \return POST_HAND_AUTH_ERROR  送付後認証が許可されていない場合。
    \return MEMORY_E  動的メモリ割り当てが失敗した場合

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_request_certificate(ssl);
    if (ret == WANT_WRITE) {
        // need to call again when I/O ready
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // failed to request a client certificate
    }
    \endcode
    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_write
*/
int  wolfSSL_request_certificate(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は楕円曲線グループのリストを設定して、WolfSSLコンテキストを希望の順に設定します。リストはヌル終了したテキスト文字列、およびコロン区切りリストです。この関数を呼び出して、TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定します。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in] list 楕円曲線グループのコロン区切りリストである文字列をリストします。
    \return WOLFSSL_FAILURE  ポインタパラメータがNULLの場合、wolfssl_max_group_countグループが多い場合は、グループ名が認識されないか、TLS v1.3を使用していません。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ctx, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_CTX_set1_groups_list(WOLFSSL_CTX *ctx, char *list);

/*!
    \ingroup Setup
    \brief  この関数は楕円曲線グループのリストを設定して、WolfSSLを希望の順に設定します。リストはヌル終了したテキスト文字列、およびコロン区切りリストです。この関数を呼び出して、TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定します。
    \param [in,out]  ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] list 鍵交換グループのコロン区切りリストである文字列をリストします。
    \return WOLFSSL_FAILURE  ポインタパラメータがNULLの場合、wolfssl_max_group_countグループが多い場合は、グループ名が認識されないか、TLS v1.3を使用していません。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_set1_groups_list(WOLFSSL *ssl, char *list);

/*!
    \ingroup TLS
    \brief  この関数は、クライアントがTLS v1.3ハンドシェイクで使用することを好む鍵交換グループを返します。この情報を完了した後にこの機能を呼び出して、サーバーがどのグループが予想されるようにこの情報が将来の接続で使用できるようになるかを決定するために、この情報が将来の接続で鍵交換のための鍵ペアを事前生成することができます。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  サーバーで呼び出された場合。
    \return NOT_READY_ERROR  ハンドシェイクが完了する前に呼び出された場合。

    _Example_
    \code
    int ret;
    int group;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl)
    if (ret < 0) {
        // failed to get group
    }
    group = ret;
    \endcode
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
*/
int  wolfSSL_preferred_group(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は楕円曲線グループのリストを設定して、WolfSSLコンテキストを希望の順に設定します。リストは、Countで指定された識別子の数を持つグループ識別子の配列です。この関数を呼び出して、TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定します。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in] groups 識別子によって鍵交換グループのリストをグループ化します。
    \param [in] count グループ内の鍵交換グループの数を数えます。
    \return BAD_FUNC_ARG  ポインタパラメータがNULLの場合、グループ数はwolfssl_max_group_countを超えているか、TLS v1.3を使用していません。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    int* groups = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = 2;
    ...
    ret = wolfSSL_CTX_set1_groups_list(ctx, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode
    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_CTX_set_groups(WOLFSSL_CTX* ctx, int* groups,
    int count);

/*!
    \ingroup Setup
    \brief  この関数は、wolfsslを許すために楕円曲線グループのリストを設定します。リストは、Countで指定された識別子の数を持つグループ識別子の配列です。この関数を呼び出して、TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定します。
    \param [in,out]  ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in]  groups 識別子によって鍵交換グループのリストをグループ化します。
    \param [in]  count グループ内の鍵交換グループの数を数えます。
    \return BAD_FUNC_ARG  ポインタパラメータがNULLの場合、グループ数がWolfSSL_MAX_GROUP_COUNTを超えている場合、任意の識別子は認識されないか、TLS v1.3を使用していません。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int* groups = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = 2;
    ...
    ret = wolfSSL_set_groups(ssl, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_set_groups(WOLFSSL* ssl, int* groups, int count);

/*!
    \ingroup IO
    \brief  この関数はクライアント側で呼び出され、サーバーとのTLS v1.3ハンドシェイクを開始します。
    この関数が呼び出されると、下層の通信チャネルはすでに設定されています。
     wolfSSL_connect()は、ブロックとノンブロックI/Oの両方で動作します。
     下層I/Oがノンブロッキングの場合、wolfSSL_connect()は、下層I/Oがwolfssl_connectの要求を満たすことができなかったときに戻ります。
     この場合、wolfSSL_get_error()への呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを生成します。
     通話プロセスは、下層I/OがREADYおよびWOLFSSLが停止したときにwolfssl_connect()への呼び出しを繰り返す必要があります。
     ノンブロッキングソケットを使用する場合は、何も実行する必要がありますが、select()を使用して必要な条件を確認できます。
     基礎となる入出力がブロックされている場合、wolfssl_connect()はハンドシェイクが終了したら、またはエラーが発生したらのみ戻ります。
     WolfSSLはOpenSSLよりも証明書検証に異なるアプローチを取ります。
     クライアントのデフォルトポリシーはサーバーを確認することです。
     これは、CASを読み込まない場合、サーバーを確認することができ、確認できません（-155）。
     SSL_CONNECTを持つことのOpenSSLの動作が成功した場合は、サーバーを検証してセキュリティを抑えることができます。
     SSL_CTX_SET_VERIFY（CTX、SSL_VERIFY_NONE、0）。
     ssl_new()を呼び出す前に。お勧めできませんが。
    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FATAL_ERROR  エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出します。
    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_connect_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept_TLSv13
    \sa wolfSSL_accept
*/
int  wolfSSL_connect_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief  この関数はサーバー側で呼び出され、SSL/TLSクライアントがSSL/TLSハンドシェイクを開始するのを待ちうけます。
    この関数が呼び出されると、下層の通信チャネルはすでに設定されています。
    wolfSSL_accept()は、ブロックとノンブロッキングI/Oの両方で動作します。
    下層の入出力がノンブロッキングである場合、wolfSSL_accept()は、下層のI/OがwolfSSL_acceptの要求を満たすことができなかったときに戻ります。
    この場合、wolfSSL_get_error()への呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを生成します。
    通話プロセスは、読み取り可能なデータが使用可能であり、wolfsslが停止した場所を拾うときに、wolfssl_acceptの呼び出しを繰り返す必要があります。
    ノンブロッキングソケットを使用する場合は、何も実行する必要がありますが、select()を使用して必要な条件を確認できます。
    下層のI/Oがブロックされている場合、wolfssl_accept()はハンドシェイクが終了したら、またはエラーが発生したら戻ります。
    古いバージョンのClientHelloメッセージがサポートされていますが、TLS v1.3接続を期待するときにこの関数を呼び出します。

    \return SSL_SUCCESS  成功時に返されます。
    \return SSL_FATAL_ERROR  エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出します。
    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_accept_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    \sa wolfSSL_get_error
    \sa wolfSSL_connect_TLSv13
    \sa wolfSSL_connect
    \sa wolfSSL_accept_TLSv13
    \sa wolfSSL_accept
*/
wolfSSL_accept_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は、WolfSSLコンテキストを使用してTLS V1.3サーバーによって受け入れられるアーリーデータの最大量を設定します。
    この関数を呼び出して、再生攻撃を軽減するためのプロセスへのアーリーデータの量を制限します。
    初期のデータは、セッションチケットが送信されたこと、したがってセッションチケットが再開されるたびに同じ接続の鍵から派生した鍵によって保護されます。
    値は再開のためにセッションチケットに含まれています。
    ゼロの値は、セッションチケットを使用してクライアントによってアーリーデータを送信することを示します。
    アーリーデータバイト数をアプリケーションで実際には可能な限り低く保つことをお勧めします。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in]  sz バイト単位で受け入れるアーリーデータのサイズ。
    \return BAD_FUNC_ARG  CTXがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  クライアントで呼び出された場合。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_set_max_early_data(ctx, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode
    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_CTX_set_max_early_data(WOLFSSL_CTX* ctx,
    unsigned int sz);

/*!
    \ingroup Setup
    \brief  この関数は、WolfSSLコンテキストを使用してTLS V1.3サーバーによって受け入れられるアーリーデータの最大量を設定します。
    この関数を呼び出して、再生攻撃を軽減するためプロセスへのアーリーデータの量を制限します。
    初期のデータは、セッションチケットが送信されたこと、したがってセッションチケットが再開されるたびに同じ接続の鍵から派生した鍵によって保護されます。
    値は再開のためにセッションチケットに含まれています。
    ゼロの値は、セッションチケットを使用してクライアントによってアーリーデータを送信することを示します。
    アーリーデータバイト数をアプリケーションで実際には可能な限り低く保つことをお勧めします。
    \param [in,out]   ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in]  SZクライアントからバイト単位で受け入れるアーリーデータのサイズ。
    \return BAD_FUNC_ARG  sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR  クライアントで呼び出された場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_set_max_early_data(ssl, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode
    \sa wolfSSL_CTX_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_set_max_early_data(WOLFSSL* ssl, unsigned int sz);

/*!
    \ingroup IO
    \brief  この関数は、セッション再開時にサーバーにアーリーデータを書き込みます。
    wolfSSL_connect()またはwolfSSL_connect_tlsv13()の代わりにこの関数を呼び出して、サーバーに接続してハンドシェイクにデータを送ります。
    この機能はクライアントでのみ使用されます。
    \return BAD_FUNC_ARG  ポインタパラメータがNULLの場合に返されます。szは0未満またはTLSV1.3を使用しない場合にも返されます。
    \return SIDE_ERROR  サーバーで呼び出された場合に返されます。
    \return WOLFSSL_FATAL_ERROR  接続が行われていない場合に返されます。

    \param [in,out]  ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in]  data アーリーデータを保持しているバッファへのポインタ。
    \param [in]  sz 書き込むアーリーデータのサイズ
    \param [out]  outSz 書き込んだアーリーデータのサイズ

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    byte earlyData[] = { early data };
    int outSz;
    char buffer[80];
    ...

    ret = wolfSSL_write_early_data(ssl, earlyData, sizeof(earlyData), &outSz);
    if (ret != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
        goto err_label;
    }
    if (outSz < sizeof(earlyData)) {
        // not all early data was sent
    }
    ret = wolfSSL_connect_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    \sa wolfSSL_read_early_data
    \sa wolfSSL_connect
    \sa wolfSSL_connect_TLSv13
*/
int  wolfSSL_write_early_data(WOLFSSL* ssl, const void* data,
    int sz, int* outSz);

/*!
    \ingroup IO
    \brief  この関数は、再開時にクライアントからの早期データを読み取ります。wolfssl_accept()またはwolfssl_accept_tlsv13()の代わりにこの関数を呼び出して、クライアントを受け入れ、ハンドシェイク内の早期データを読み取ります。ハンドシェイクよりも早期データがない場合は、通常として処理されます。この機能はサーバーでのみ使用されます。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [out]  データはクライアントから読み込まれた早期データを保持するためのバッファ。
    \param [in]  バッファのSZサイズバイト数。
    \param [out]  OUTSZ初期データのバイト数。
    \return BAD_FUNC_ARG  ポインタパラメータがNULLの場合、SZは0未満またはTLSV1.3を使用しない。
    \return SIDE_ERROR  クライアントで呼び出された場合。
    \return WOLFSSL_FATAL_ERROR  接続を受け入れると失敗した場合

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    byte earlyData[128];
    int outSz;
    char buffer[80];
    ...

    ret = wolfSSL_read_early_data(ssl, earlyData, sizeof(earlyData), &outSz);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    if (outSz > 0) {
        // early data available
    }
    ret = wolfSSL_accept_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    \sa wolfSSL_write_early_data
    \sa wolfSSL_accept
    \sa wolfSSL_accept_TLSv13
*/
int  wolfSSL_read_early_data(WOLFSSL* ssl, void* data, int sz,
    int* outSz);

/*!
    \ingroup Setup
    \brief  この関数は、TLS v1.3接続のプレシェア鍵（PSK）クライアント側コールバックを設定します。コールバックはPSKアイデンティティを見つけ、そのキーと、ハンドシェイクに使用する暗号の名前を返します。この関数は、WOLFSSL_CTX構造体のclient_psk_tls13_cbメンバーを設定します。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    ...
    wolfSSL_CTX_set_psk_client_tls13_callback(ctx, my_psk_client_tls13_cb);
    \endcode
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_CTX_set_psk_client_tls13_callback(WOLFSSL_CTX* ctx,
    wc_psk_client_tls13_callback cb);

/*!
    \ingroup Setup
    \brief  この関数は、TLS v1.3接続のプレシェアキー（PSK）クライアント側コールバックを設定します。コールバックはPSKアイデンティティを見つけ、そのキーと、ハンドシェイクに使用する暗号の名前を返します。この関数は、wolfssl構造体のOptionsフィールドのclient_psk_tls13_cbメンバーを設定します。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_set_psk_client_tls13_callback(ssl, my_psk_client_tls13_cb);
    \endcode
    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_set_psk_client_tls13_callback(WOLFSSL* ssl,
    wc_psk_client_tls13_callback cb);

/*!
    \ingroup Setup
    \brief  この関数は、TLS v1.3接続用の事前共有鍵（PSK）サーバ側コールバックを設定します。コールバックはPSKアイデンティティを見つけ、そのキーと、ハンドシェイクに使用する暗号の名前を返します。この関数は、wolfssl_ctx構造体のserver_psk_tls13_cbメンバーを設定します。
    \param [in,out]  ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    ...
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, my_psk_client_tls13_cb);
    \endcode
    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_CTX_set_psk_server_tls13_callback(WOLFSSL_CTX* ctx,
    wc_psk_server_tls13_callback cb);

/*!
    \ingroup Setup
    \brief  この関数は、TLS v1.3接続用の事前共有鍵（PSK）サーバ側コールバックを設定します。コールバックはPSKアイデンティティを見つけ、そのキーと、ハンドシェイクに使用する暗号の名前を返します。この関数は、wolfssl構造体のオプションフィールドのserver_psk_tls13_cbメンバーを設定します。
    \param [in,out]    ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_set_psk_server_tls13_callback(ssl, my_psk_server_tls13_cb);
    \endcode
    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
*/
void wolfSSL_set_psk_server_tls13_callback(WOLFSSL* ssl,
    wc_psk_server_tls13_callback cb);

/*!
    \ingroup Setup
    \brief  この関数は、キーペアの生成を含むグループからキーシェアエントリを作成します。Keyshareエクステンションには、鍵交換のための生成されたすべての公開鍵が含まれています。この関数が呼び出されると、指定されたグループのみが含まれます。優先グループがサーバーに対して以前に確立されているときにこの関数を呼び出します。
    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in]  キー交換グループ識別子をグループ化します。
    \return BAD_FUNC_ARG  sslがNULLの場合に返されます。
    \return MEMORY_E  動的メモリ割り当てに失敗すると返されます。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set key share
    }
    \endcode
    \sa wolfSSL_preferred_group
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_NoKeyShares
*/
int wolfSSL_UseKeyShare(WOLFSSL* ssl, word16 group);

/*!
    \ingroup Setup
    \brief  この関数は、ClientHelloで鍵共有が送信されないように呼び出されます。これにより、ハンドシェイクに鍵交換が必要な場合は、サーバーがHelloretryRequestで応答するように強制します。予想される鍵交換グループが知られておらず、キーの生成を不必要に回避するときにこの機能を呼び出します。鍵交換が必要なときにハンドシェイクを完了するために追加の往復が必要になることに注意してください。
    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \return BAD_FUNC_ARG  sslがNULLの場合に返されます。
    \return SIDE_ERROR  サーバーで呼び出された場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_NoKeyShares(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set no key shares
    }
    \endcode
    \sa wolfSSL_UseKeyShare
*/
int wolfSSL_NoKeyShares(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief  この関数は、アプリケーションがサーバーであることを示すために使用され、TLS 1.3プロトコルのみをサポートします。この関数は、wolfSSL_CTX_new()を使用してSSL / TLSコンテキストを作成するときに使用される新しいWolfssl_method構造体のメモリを割り当てて初期化します。
    \param [in]  ヒープ静的メモリ割り当て中に静的メモリ割り当て器が使用するバッファへのポインタを使用します。
    \return 新しく作成されたwWOLFSSL_METHOS構造体へのポインタを返します。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method_ex(NULL);
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief  この関数は、アプリケーションがクライアントであることを示すために使用され、TLS 1.3プロトコルのみをサポートします。この関数は、wolfSSL_CTX_new()を使用してSSL / TLSコンテキストを作成するときに使用される新しいWolfssl_method構造体のメモリを割り当てて初期化します。
    \param [in]  ヒープ静的メモリ割り当て中に静的メモリ割り当て器が使用するバッファへのポインタを使用します。
    \return 新しく作成されたwWOLFSSL_METHOS構造体へのポインタを返します。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_client_method_ex(NULL);
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief  この関数は、アプリケーションがサーバーであることを示すために使用され、TLS 1.3プロトコルのみをサポートします。この関数は、wolfSSL_CTX_new()を使用してSSL / TLSコンテキストを作成するときに使用される新しいWolfssl_method構造体のメモリを割り当てて初期化します。
    \return 新しく作成されたwWOLFSSL_METHOS構造体へのポインタを返します。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method_ex
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_server_method(void);

/*!
    \ingroup Setup
    \brief  この関数は、アプリケーションがクライアントであることを示すために使用され、TLS 1.3プロトコルのみをサポートします。この関数は、wolfSSL_CTX_new()を使用してSSL / TLSコンテキストを作成するときに使用される新しいWolfssl_method構造体のメモリを割り当てて初期化します。
    \return 新しく作成されたwWOLFSSL_METHOS構造体へのポインタを返します。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_client_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method_ex
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_client_method(void);

/*!
    \ingroup Setup
    \brief  この関数は、まだどちらの側（サーバ/クライアント）を決定していないことを除いて、Wolftlsv1_3_client_methodと同様のwolfssl_methodを返します。
    \param [in]  ヒープ静的メモリ割り当て中に静的メモリ割り当て器が使用するバッファへのポインタを使用します。
    \return WOLFSSL_METHOD  成功した作成では、wolfssl_methodポインタを返します

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method_ex(NULL));
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief  この関数は、まだどちらの側（サーバ/クライアント）を決定していないことを除いて、Wolftlsv1_3_client_methodと同様のwolfssl_methodを返します。
    \return WOLFSSL_METHOD  成功した作成では、wolfssl_methodポインタを返します

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method());
    // check ret value
    \endcode
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method(void);

/*!
 \ingroup Setup
 \brief  この関数はクライアント側で呼び出される場合には、サーバー側にCertificateメッセージで送信できる証明書タイプを設定します。
 サーバー側で呼び出される場合には、受入れ可能なクライアント証明書タイプを設定します。
 Raw Public Key 証明書を送受信したい場合にはこの関数を使って証明書タイプを設定しなければなりません。
 設定する証明書タイプは優先度順に格納したバイト配列として渡します。
 設定するバッファアドレスにNULLを渡すか、あるいはバッファサイズに0を渡すと規定値にもどすことができます。
 規定値はX509証明書（WOLFSSL_CERT_TYPE_X509）のみを扱う設定となっています。

 \return WOLFSSL_SUCCESS 成功
 \return BAD_FUNC_ARG ctxとしてNULLを渡した、あるいは不正な証明書タイプを指定した、
 あるいはMAX_CLIENT_CERT_TYPE_CNT以上のバッファサイズを指定した、あるいは指定の証明書タイプに重複がある
 \param ctx  wolfssl_ctxコンテキストポインタ
 \param ctype  証明書タイプを格納したバッファへのポインタ
 \param len  証明書タイプを格納したバッファのサイズ（バイト数）
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char ctype[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(ctype)/sizeof(byte);
　...

  ret = wolfSSL_CTX_set_client_cert_type(ctx, ctype, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_CTX_set_client_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  この関数はサーバー側で呼び出される場合には、クライアント側にCertificateメッセージで送信できる証明書タイプを設定します。
 クライアント側で呼び出される場合には、受入れ可能なサーバー証明書タイプを設定します。
 Raw Public Key 証明書を送受信したい場合にはこの関数を使って証明書タイプを設定しなければなりません。
 設定する証明書タイプは優先度順に格納したバイト配列として渡します。
 設定するバッファアドレスにNULLを渡すか、あるいはバッファサイズに0を渡すと規定値にもどすことができます。
 規定値はX509証明書（WOLFSSL_CERT_TYPE_X509）のみを扱う設定となっています。

 \return WOLFSSL_SUCCESS 成功
 \return BAD_FUNC_ARG ctxとしてNULLを渡した、あるいは不正な証明書タイプを指定した、
 あるいはMAX_SERVER_CERT_TYPE_CNT以上のバッファサイズを指定した、あるいは指定の証明書タイプに重複がある

 \param ctx  wolfssl_ctxコンテキストポインタ
 \param ctype  証明書タイプを格納したバッファへのポインタ
 \param len  証明書タイプを格納したバッファのサイズ（バイト数）
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char ctype[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(ctype)/sizeof(byte);
　...

  ret = wolfSSL_CTX_set_server_cert_type(ctx, ctype, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_CTX_set_server_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  この関数はクライアント側で呼び出される場合には、サーバー側にCertificateメッセージで送信できる証明書タイプを設定します。
 サーバー側で呼び出される場合には、受入れ可能なクライアント証明書タイプを設定します。
 Raw Public Key 証明書を送受信したい場合にはこの関数を使って証明書タイプを設定しなければなりません。
 設定する証明書タイプは優先度順に格納したバイト配列として渡します。
 設定するバッファアドレスにNULLを渡すか、あるいはバッファサイズに0を渡すと規定値にもどすことができます。
 規定値はX509証明書（WOLFSSL_CERT_TYPE_X509）のみを扱う設定となっています。

 \return WOLFSSL_SUCCESS 成功
 \return BAD_FUNC_ARG sslとしてNULLを渡した、あるいは不正な証明書タイプを指定した、
 あるいはMAX_CLIENT_CERT_TYPE_CNT以上のバッファサイズを指定した、あるいは指定の証明書タイプに重複がある

 \param ssl  WOLFSSL構造体へのポインタ
 \param ctype  証明書タイプを格納したバッファへのポインタ
 \param len  証明書タイプを格納したバッファのサイズ（バイト数）
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  char ctype[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(ctype)/sizeof(byte);
　...

  ret = wolfSSL_set_client_cert_type(ssl, ctype, len);
 \endcode
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_set_client_cert_type(WOLFSSL* ssl, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  この関数はサーバー側で呼び出される場合には、クライアント側にCertificateメッセージで送信できる証明書タイプを設定します。
 クライアント側で呼び出される場合には、受入れ可能なサーバー証明書タイプを設定します。
 Raw Public Key 証明書を送受信したい場合にはこの関数を使って証明書タイプを設定しなければなりません。
 設定する証明書タイプは優先度順に格納したバイト配列として渡します。
 設定するバッファアドレスにNULLを渡すか、あるいはバッファサイズに0を渡すと規定値にもどすことができます。
 規定値はX509証明書（WOLFSSL_CERT_TYPE_X509）のみを扱う設定となっています。

 \return WOLFSSL_SUCCESS 成功
 \return BAD_FUNC_ARG ctxとしてNULLを渡した、あるいは不正な証明書タイプを指定した、
 あるいはMAX_SERVER_CERT_TYPE_CNT以上のバッファサイズを指定した、あるいは指定の証明書タイプに重複がある

 \param ssl  WOLFSSL構造体へのポインタ
 \param ctype  証明書タイプを格納したバッファへのポインタ
 \param len  証明書タイプを格納したバッファのサイズ（バイト数）
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  char ctype[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(ctype)/sizeof(byte);
　...

  ret = wolfSSL_set_server_cert_type(ssl, ctype, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_set_server_cert_type(WOLFSSL* ssl, const char* buf, int len);

/*!
 \ingroup SSL
 \brief  この関数はハンドシェーク終了後に呼び出し、相手とのネゴシエーションの結果得られたクライアント証明書のタイプを返します。
 ネゴシエーションが発生しない場合には戻り値としてWOLFSSL_SUCCESSが返されますが、
 証明書タイプとしてはWOLFSSL_CERT_TYPE_UNKNOWNが返されます。

 \return WOLFSSL_SUCCESS 成功時にかえります。tpに返された証明書タイプはWOLFSSL_CERT_TYPE_X509,
  WOLFSSL_CERT_TYPE_RPK あるいはWOLFSSL_CERT_TYPE_UNKNOWNのいずれかとなります。
 \return BAD_FUNC_ARG sslとしてNULLを渡した、あるいはtpとしてNULLを渡した
 \param ssl  WOLFSSL構造体へのポインタ
 \param tp  証明書タイプが返されるバッファへのポインタ
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  int tp;
　...

  ret = wolfSSL_get_negotiated_client_cert_type(ssl, &tp);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_get_negotiated_client_cert_type(WOLFSSL* ssl, int* tp);

/*!
 \ingroup SSL
 \brief  この関数はハンドシェーク終了後に呼び出し、相手とのネゴシエーションの結果得られたサーバー証明書のタイプを返します。
 ネゴシエーションが発生しない場合には戻り値としてWOLFSSL_SUCCESSが返されますが、証明書タイプとしてはWOLFSSL_CERT_TYPE_UNKNOWNが返されます。
 \return WOLFSSL_SUCCESS 成功時にかえります。tpに返された証明書タイプはWOLFSSL_CERT_TYPE_X509,
  WOLFSSL_CERT_TYPE_RPK あるいはWOLFSSL_CERT_TYPE_UNKNOWNのいずれかとなります。
 \return BAD_FUNC_ARG sslとしてNULLを渡した、あるいはtpとしてNULLを渡した
 \param ssl  WOLFSSL構造体へのポインタ
 \param tp  証明書タイプが返されるバッファへのポインタ
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  int tp;
　...

  ret = wolfSSL_get_negotiated_server_cert_type(ssl, &tp);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 */
int wolfSSL_get_negotiated_server_cert_type(WOLFSSL* ssl, int* tp);

/*!
 \ingroup SSL
 \brief  この関数はテストのための固定/静的なエフェラルキーを設定します。
 \return 0  成功時に返されます。
 \param ctx  WOLFSSL_CTXコンテキストポインタ
 \param keyAlgo  WC_PK_TYPE_DHおよびWC_PK_TYPE_ECDHのようなenum wc_pktype
 \param key  キーファイルパス（Keysz == 0）または実際のキーバッファ（PEMまたはASN.1）
 \param keySz  キーサイズ（「キー」argはファイルパスの場合は0になります）
 \sa wolfSSL_CTX_get_ephemeral_key
 */
int wolfSSL_CTX_set_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief  この関数はテストのための固定/静的なエフェラルキーを設定します。
 \return 0  成功時に返されます。
 \param ssl  WOLFSSL構造体へのポインタ
 \param keyAlgo  WC_PK_TYPE_DHおよびWC_PK_TYPE_ECDHのようなenum wc_pktype
 \param key  キーファイルパス（Keysz == 0）または実際のキーバッファ（PEMまたはASN.1）
 \param keySz  キーサイズ（「キー」argはファイルパスの場合は0になります）
 \sa wolfSSL_get_ephemeral_key
 */
int wolfSSL_set_ephemeral_key(WOLFSSL* ssl, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief  この関数は ASN.1/DERとしてロードされたキーへのポインタを返します
 \return 0  成功時に返されます。
 \param ctx  wolfssl_ctxコンテキストポインタ
 \param keyAlgo  WC_PK_TYPE_DHおよびWC_PK_TYPE_ECDHのようなenum wc_pktype
 \param key  キーバッファポインタ
 \sa wolfSSL_CTX_set_ephemeral_key
 */
int wolfSSL_CTX_get_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief  この関数は ASN.1/DERとしてロードされた鍵へのポインタを返します
 \return 0  成功時に返されます。
 \param ssl  WOLFSSL構造体へのポインタ
 \param keyAlgo  WC_PK_TYPE_DHおよびWC_PK_TYPE_ECDHのようなenum wc_pktype
 \param key  キーバッファポインタ
 \sa wolfSSL_set_ephemeral_key
 */
int wolfSSL_get_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief  選択したメッセージダイジェスト、パディング、およびRSAキーを使用してメッセージに署名します。
 \return WOLFSSL_SUCCESS  成功時に返されます。
 \return WOLFSSL_FAILURE  エラー発生時に返されます。

 \param type  ハッシュNID
 \param m  署名するメッセージ。これは署名するメッセージのダイジェスト
 \param mLen  署名するメッセージの長さ
 \param sigRet  出力バッファへのポインタ
 \param sigLen 入力時にはsigRetの長さを指定します。出力時にはsigRetに書き込まれたデータの長さを格納します。
 \param rsa  入力に署名するために使用されるRSA鍵
 \param flag  1：シグニチャ0：未パワード署名を比較する値を出力します。注：RSA_PKCS1_PSS_PADDINGの場合は、wc_rsapss_checkpadding_ex関数を使用して* VERIFY *関数の出力を確認する必要があります。
 \param padding パディング
 */
int wolfSSL_RSA_sign_generic_padding(int type, const unsigned char* m,
                               unsigned int mLen, unsigned char* sigRet,
                               unsigned int* sigLen, WOLFSSL_RSA* rsa,
                               int flag, int padding);

/*!
　\ingroup SSL
　\brief DTLSv1.3 送信済みだがまだ相手からアクノリッジを受けとっていないメッセージがあるか調べます。

 \return 1 ペンディングのメッセージがある場合に返されます。それ以外は0が返されます。
 \param ssl WOLFSSL構造体へのポインタ。
*/
int wolfSSL_dtls13_has_pending_msg(WOLFSSL *ssl);

/*!
    \ingroup SSL
    \brief アーリーデータの最大サイズを取得します。

    \param [in] s  WOLFSSL_SESSION構造体へのポインタ

    \return アーリーデータの最大サイズ（max_early_data）
    \param s WOLFSSL_SESSION構造体へのポインタ

    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
 */
unsigned int wolfSSL_SESSION_get_max_early_data(const WOLFSSL_SESSION *s);

/*!
    \ingroup SSL
    \brief Get a new index for external data. This entry applies also for the
           following API:
           - wolfSSL_CTX_get_ex_new_index
           - wolfSSL_get_ex_new_index
           - wolfSSL_SESSION_get_ex_new_index
           - wolfSSL_X509_get_ex_new_index

    \param [in] All input parameters are ignored. The callback functions are not
                supported with wolfSSL.

    \return The new index value to be used with the external data API for this
            object class.
 */
int wolfSSL_CRYPTO_get_ex_new_index(int, void*, void*, void*, void*);

/*!

 \brief コネクションID拡張を有効にします。RFC9146とRFC9147を参照してください。

 \return WOLFSSL_SUCCESS 成功時に返されます。それ以外はエラーコードが返されます。

 \param ssl WOLFSSL構造体へのポインタ。

 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_use(WOLFSSL* ssl);

/*!

 \brief この関数はハンドシェークが完了した後に呼び出されると、コネクションIDがネゴシエートされたかどうか確認することができます。
 RFC9146とRFC9147を参照してください。

 \return 1 コネクションIDがネゴシエートされた場合に返されます。それ以外は0が返されます。

 \param ssl WOLFSSL構造体へのポインタ。

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_is_enabled(WOLFSSL* ssl);

/*!

 \brief このコネクションで他のピアに対してレコードを送信するためのコネクションIDをセットします。
 RFC9146とRFC9147を参照してください。コネクションIDは最大値がDTLS_CID_MAX_SIZEでなければなりません。
 DTLS_CID_MAX_SIZEはビルド時に値を指定が可能ですが255バイトをこえることはできません。


 \return WOLFSSL_SUCCESS コネクションIDがセットできた場合に返されます。それ以外はエラーコードが返されます。

 \param ssl WOLFSSL構造体へのポインタ。
 \param cid コネクションID
 \param size コネクションIDのサイズ

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid,
    unsigned int size);

/*!

 \brief コネクションIDのサイズを取得します。RFC9146とRFC9147を参照してください。

 \return WOLFSSL_SUCCESS コネクションIDが取得できた場合に返されます。それ以外はエラーコードが返されます。

 \param ssl WOLFSSL構造体へのポインタ。
 \param size コネクションIDのサイズを格納するint型変数へのポインタ。

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_rx_size(WOLFSSL* ssl,
    unsigned int* size);

/*!

 \brief コネクションIDを引数bufferで指定されたバッファにコピーします。
 RFC9146とRFC9147を参照してください。
 バッファのサイズは引数bufferSzで指定してください。

 \return WOLFSSL_SUCCESS コネクションIDが取得できた場合に返されます。それ以外はエラーコードが返されます。

 \param ssl WOLFSSL構造体へのポインタ。
 \param buffer コネクションIDがコピーされる先のバッファへのポインタ。
 \param bufferSz バッファのサイズ

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_rx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);

/*!

 \brief コネクションIDのサイズを取得します。ｃ
 サイズは引数size変数に格納されます。

 \return WOLFSSL_SUCCESS コネクションIDのサイズが取得できた場合に返されます。それ以外はエラーコードが返されます。

 \param ssl WOLFSSL構造体へのポインタ。
 \param size コネクションIDのサイズを格納するint型変数へのポインタ。

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_tx_size(WOLFSSL* ssl, unsigned int* size);

/*!

 \brief コネクションIDを引き数bufferで指定されるバッファにコピーします。RFC9146とRFC9147を参照してください。
 バッファのサイズは引き数bufferSzで指定します。

 \return WOLFSSL_SUCCESS ConnectionIDが正常にコピーされた際に返されます。それ以外はエラーコードが返されます。

 \param ssl WOLFSSL構造体へのポインタ。
 \param buffer ConnectionIDがコピーされるバッファへのポインタ。
 \param bufferSz バッファのサイズ

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
int wolfSSL_dtls_cid_get_tx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);
