/*!
    \brief この関数はDTLS v1.2クライアントメソッドを初期化します。

    \return pointer この関数は新しいWOLFSSL_METHOD構造体へのポインタを返します。

    \param none パラメータはありません。

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

    \brief この関数はwolfSSLv23_client_methodに似たWOLFSSL_METHODを返しますが、どちら側(サーバ/クライアント)であるかがまだ決定されていない点が異なります。

    \return WOLFSSL_METHOD* 正常に作成された場合、WOLFSSL_METHODポインタを返します
    \return NULL メモリ割り当てエラーまたはメソッド作成失敗の場合はNullを返します

    \param none パラメータはありません。

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfSSLv23_method());
    // ret値をチェック
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfSSLv23_method(void);

/*!
    \ingroup Setup

    \brief wolfSSLv3_server_method()関数は、アプリケーションがサーバであり、SSL 3.0プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_server_method();
    if (method == NULL) {
	    メソッドを取得できません
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

    \brief wolfSSLv3_client_method()関数は、アプリケーションがクライアントであり、SSL 3.0プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
	    メソッドを取得できません
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

    \brief wolfTLSv1_server_method()関数は、アプリケーションがサーバであり、TLS 1.0プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_server_method();
    if (method == NULL) {
	    メソッドを取得できません
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

    \brief wolfTLSv1_client_method()関数は、アプリケーションがクライアントであり、TLS 1.0プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_client_method();
    if (method == NULL) {
	    メソッドを取得できません
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

    \brief wolfTLSv1_1_server_method()関数は、アプリケーションがサーバであり、TLS 1.1プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_server_method();
    if (method == NULL) {
        // メソッドを取得できません
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

    \brief wolfTLSv1_1_client_method()関数は、アプリケーションがクライアントであり、TLS 1.0プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_client_method();
    if (method == NULL) {
        // メソッドを取得できません
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

    \brief wolfTLSv1_2_server_method()関数は、アプリケーションがサーバであり、TLS 1.2プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_server_method();
    if (method == NULL) {
	    // メソッドを取得できません
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

    \brief wolfTLSv1_2_client_method()関数は、アプリケーションがクライアントであり、TLS 1.2プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のためのメモリを割り当てて初期化します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータはありません。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_client_method();
    if (method == NULL) {
	    // メソッドを取得できません
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
    \brief wolfDTLSv1_client_method()関数は、アプリケーションがクライアントであり、DTLS 1.0プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。この関数は、wolfSSLがDTLSサポート付きでコンパイルされている場合(--enable-dtls、またはwolfSSL_DTLSを定義することによって)にのみ利用可能です。
    \return ＊ 成功した場合、この呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます（通常はNULLで、errnoがENOMEMに設定されます）。

    \param none パラメータはありません。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_client_method();
    if (method == NULL) {
	    // メソッドを取得できません
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

    \brief wolfDTLSv1_server_method()関数は、アプリケーションがサーバーであり、DTLS 1.0プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。この関数は、wolfSSLがDTLSサポートを有効にしてコンパイルされている場合にのみ使用可能です（--enable-dtls、またはwolfSSL_DTLSを定義することによって）。

    \return ＊ 成功した場合、この呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます（通常はNULLで、errnoがENOMEMに設定されます）。

    \param none パラメータはありません。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_server_method();
    if (method == NULL) {
	    // メソッドを取得できません
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
    \ingroup Setup

    \brief wolfDTLSv1_3_server_method()関数は、アプリケーションがサーバーであり、DTLS 1.3プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。この関数は、wolfSSLがDTLSv1.3サポートを有効にしてコンパイルされている場合にのみ使用可能です（--enable-dtls13、またはwolfSSL_DTLS13を定義することによって）。

    \return ＊ 成功した場合、この呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます（通常はNULLで、errnoがENOMEMに設定されます）。

    \param none パラメータはありません。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_server_method();
    if (method == NULL) {
	    // メソッドを取得できません
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_client_method
*/

WOLFSSL_METHOD *wolfDTLSv1_3_server_method(void);
/*!
    \ingroup Setup

    \brief wolfDTLSv1_3_client_method()関数は、アプリケーションがクライアントであり、DTLS 1.3プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。この関数は、wolfSSLがDTLSv1.3サポートを有効にしてコンパイルされている場合にのみ使用可能です（--enable-dtls13、またはwolfSSL_DTLS13を定義することによって）。

    \return ＊ 成功した場合、この呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます（通常はNULLで、errnoがENOMEMに設定されます）。

    \param none パラメータはありません。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_client_method();
    if (method == NULL) {
	    // メソッドを取得できません
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_server_method
*/
WOLFSSL_METHOD* wolfDTLSv1_3_client_method(void);
/*!
    \ingroup Setup

    \brief wolfDTLS_server_method()関数は、アプリケーションがサーバーであり、利用可能な最新バージョンのDTLSおよび許可される最小バージョンまでのすべてのバージョンをサポートすることを示すために使用されます。デフォルトの許可される最小バージョンは、WOLFSSL_MIN_DTLS_DOWNGRADEの定義に基づいており、wolfSSL_SetMinVersion()を使用して実行時に変更できます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。この関数は、wolfSSLがDTLSサポートを有効にしてコンパイルされている場合にのみ使用可能です（--enable-dtls、またはwolfSSL_DTLSを定義することによって）。

    \return ＊ 成功した場合、この呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます（通常はNULLで、errnoがENOMEMに設定されます）。

    \param none パラメータはありません。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_server_method();
    if (method == NULL) {
	    // メソッドを取得できません
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

    \brief wolfDTLS_client_method()関数は、アプリケーションがクライアントであり、利用可能な最新バージョンのDTLSおよび許可される最小バージョンまでのすべてのバージョンをサポートすることを示すために使用されます。デフォルトの許可される最小バージョンは、WOLFSSL_MIN_DTLS_DOWNGRADEの定義に基づいており、wolfSSL_SetMinVersion()を使用して実行時に変更できます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。この関数は、wolfSSLがDTLSサポートを有効にしてコンパイルされている場合にのみ使用可能です（--enable-dtls、またはwolfSSL_DTLSを定義することによって）。

    \return ＊ 成功した場合、この呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます（通常はNULLで、errnoがENOMEMに設定されます）。

    \param none パラメータはありません。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_client_method();
    if (method == NULL) {
	    // メソッドを取得できません
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLS_server_method
    \sa wolfSSL_SetMinVersion
*/
WOLFSSL_METHOD *wolfDTLS_client_method(void);
/*!
    \brief この関数は、サーバー側用のWOLFSSL_METHODを作成し、初期化します。

    \return この関数はWOLFSSL_METHODポインタを返します。

    \param none パラメータはありません。

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

    \brief chacha-poly AEAD構築の最初のリリースと新しいバージョンの間にはいくつかの違いがあるため、古いバージョンを使用するサーバー/クライアントと通信するためのオプションを追加しました。デフォルトでは、wolfSSLは新しいバージョンを使用します。

    \return 0 成功時

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param value poly1305の情報を設定する際に古いバージョンを使用するかどうか。フラグ値1を渡すと古いpoly AEADを使用することを示し、新しいバージョンの使用に戻すにはフラグ値0を渡します。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_use_old_poly(ssl, 1);
    if (ret != 0) {
        // poly1305 AEADバージョンの設定に失敗しました
    }
    \endcode

    \sa none
*/
int wolfSSL_use_old_poly(WOLFSSL* ssl, int value);

/*!
    \brief wolfSSL_dtls_import()関数は、シリアル化されたセッション状態を解析するために使用されます。これにより、ハンドシェイクが完了した後に接続を再開できます。

    \return Success 成功した場合、読み取られたバッファの量が返されます。
    \return Failure すべての失敗した戻り値は0未満になります。
    \return VERSION_ERROR バージョンの不一致が見つかった場合、つまりDTLS v1でctxがDTLS v1.2用に設定されている場合、VERSION_ERRORが返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf インポートするシリアル化されたセッション。
    \param sz シリアル化されたセッションバッファのサイズ。

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    // wc_dtls_export関数から送信された情報を取得し、bufに配置します
    fread(buf, 1, bufSz, input);
    ret = wolfSSL_dtls_import(ssl, buf, bufSz);
    if (ret < 0) {
        // エラーケースを処理します
    }
    // ハンドシェイクが既に完了しているため、wolfSSL_acceptは不要です
    ...
    ret = wolfSSL_write(ssl) および wolfSSL_read(ssl);
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
int wolfSSL_dtls_import(WOLFSSL* ssl, unsigned char* buf,
                                                               unsigned int sz);


/*!
    \brief シリアル化されたTLSセッションをインポートするために使用されます。この関数は、接続の状態をインポートするためのものです。警告：bufには状態に関する機密情報が含まれており、保存する場合は暗号化してから保存するのが最善です。マクロWOLFSSL_SESSION_EXPORT_DEBUGを定義することで、追加のデバッグ情報を表示できます。

    \return バッファ'buf'から読み取られたバイト数

    \param ssl セッションをインポートするWOLFSSL構造体
    \param buf シリアル化されたセッション
    \param sz  バッファ'buf'のサイズ

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_export
 */
int wolfSSL_tls_import(WOLFSSL* ssl, const unsigned char* buf,
        unsigned int sz);

/*!
    \brief wolfSSL_CTX_dtls_set_export()関数は、セッションをエクスポートするためのコールバック関数を設定するために使用されます。以前に保存されたエクスポート関数をクリアするために、パラメータfuncとしてNULLを渡すことができます。サーバー側で使用され、ハンドシェイクが完了した直後に呼び出されます。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG nullまたは期待されない引数が渡された場合

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param func セッションをエクスポートする際に使用するwc_dtls_export関数。

    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // buf（シリアル化されたセッション）を宛先に渡すsend session（wc_dtls_export）の本体
    WOLFSSL_CTX* ctx;
    int ret;
    ...
    ret = wolfSSL_CTX_dtls_set_export(ctx, send_session);
    if (ret != SSL_SUCCESS) {
        // エラーケースを処理します
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
int wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx,
                                                           wc_dtls_export func);

/*!
    \brief wolfSSL_dtls_set_export()関数は、セッションをエクスポートするためのコールバック関数を設定するために使用されます。以前に保存されたエクスポート関数をクリアするために、パラメータfuncとしてNULLを渡すことができます。サーバー側で使用され、ハンドシェイクが完了した直後に呼び出されます。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG nullまたは期待されない引数が渡された場合

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param func セッションをエクスポートする際に使用するwc_dtls_export関数。

    _Example_
    \code    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // send sessionの本体(wc_dtls_export)
    // buf(シリアライズされたセッション)を宛先に渡す
    WOLFSSL* ssl;
    int ret;
    ...
    ret = wolfSSL_dtls_set_export(ssl, send_session);
    if (ret != SSL_SUCCESS) {
        // エラーケースの処理
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
    \brief wolfSSL_dtls_export()関数は、WOLFSSLセッションを提供されたバッファにシリアライズするために使用されます。セッションを送信するための関数コールバックを使用するよりもメモリオーバーヘッドが少なく、セッションをシリアライズするタイミングを選択できます。関数に渡されたときにbufferがNULLの場合、szはWOLFSSLセッションをシリアライズするために必要なバッファのサイズに設定されます。

    \return Success 成功した場合、使用されたバッファの量が返されます。
    \return Failure すべての失敗時の戻り値は0未満になります。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf シリアライズされたセッションを保持するバッファ。
    \param sz バッファのサイズ。

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    ret = wolfSSL_dtls_export(ssl, buf, bufSz);
    if (ret < 0) {
        // エラーケースの処理
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
    \brief シリアライズされたTLSセッションをエクスポートするために使用されます。この関数は接続のシリアライズされた状態をエクスポートするためのものです。
    ほとんどの場合、wolfSSL_tls_exportの代わりにwolfSSL_get1_sessionを使用する必要があります。
    追加のデバッグ情報は、マクロWOLFSSL_SESSION_EXPORT_DEBUGが定義されている場合に表示できます。
    警告: bufには状態に関する機密情報が含まれているため、保存する場合は暗号化してから保存することが最善です。

    \return バッファ'buf'に書き込まれたバイト数

    \param ssl セッションをエクスポートするWOLFSSL構造体
    \param buf シリアライズされたセッションの出力
    \param sz  'buf'に設定されたバイト単位のサイズ

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_import
 */
int wolfSSL_tls_export(WOLFSSL* ssl, unsigned char* buf,
        unsigned int* sz);

/*!
    \brief この関数は、CTX用の静的メモリを確保するために使用されます。確保されたメモリは、CTXのライフタイム中およびCTXから作成されたSSLオブジェクトに使用されます。NULLのctxポインタとwolfSSL_method_func関数を渡すことで、CTX自体の作成も静的メモリを使用します。wolfSSL_method_funcは、WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);という関数シグネチャを持ちます。maxに0を渡すと、設定されていないかのように動作し、最大同時使用制限は適用されません。渡されたflag値は、メモリの使用方法と動作中の挙動を決定します。利用可能なフラグは次のとおりです: 0 - デフォルトの一般メモリ、WOLFMEM_IO_POOL - メッセージの送受信時の入出力バッファに使用され、一般メモリをオーバーライドするため、渡されたバッファ内のすべてのメモリがIOに使用されます、WOLFMEM_IO_FIXED - WOLFMEM_IO_POOLと同じですが、各SSLがライフタイム中に2つのバッファを保持します、WOLFMEM_TRACK_STATS - 各SSLが実行中にメモリ統計を追跡します。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE 失敗時。

    \param ctx WOLFSSL_CTX構造体へのポインタのアドレス。
    \param method プロトコルを作成する関数。(ctxもNULLでない場合はNULLであるべきです)
    \param buf すべての操作に使用するメモリ。
    \param sz 渡されるメモリバッファのサイズ。
    \param flag メモリのタイプ。
    \param max 最大同時操作数。

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
    // 静的メモリを使用してctxも作成、使用する一般メモリから開始
    ctx = NULL:
    ret = wolfSSL_CTX_load_static_memory(&ctx, wolfSSLv23_server_method_ex,
    memory, memorySz, 0,    MAX_CONCURRENT_HANDSHAKES);
    if (ret != SSL_SUCCESS) {
        // エラーケースの処理
    }
    // IOで使用するメモリをロード
    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL, IO, IOSz, flag,
    MAX_CONCURRENT_IO);
    if (ret != SSL_SUCCESS) {
        // エラーケースの処理
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
    \brief この関数は接続の動作を変更せず、静的メモリの使用状況に関する情報を収集するためにのみ使用されます。

    \return 1 CTXが静的メモリを使用している場合にtrueとして返されます。
    \return 0 静的メモリを使用していない場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param mem_stats 静的メモリの使用状況に関する情報を保持する構造体。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int ret;
    WOLFSSL_MEM_STATS mem_stats;
    ...
    //CTXによる静的メモリに関する情報を取得
    ret = wolfSSL_CTX_is_static_memory(ctx, &mem_stats);
    if (ret == 1) {
        // 静的メモリを使用しているケースの処理
        // mem_statsの要素を出力または検査
    }
    if (ret == 0) {
        //ctxが静的メモリを使用していないケースの処理
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
    \brief wolfSSL_is_static_memoryは、SSLの静的メモリ使用状況に関する情報を収集するために使用されます。戻り値は静的メモリが使用されているかどうかを示し、WOLFSSL_MEM_CONN_STATSは、静的メモリをロードする際に親CTXにWOLFMEM_TRACK_STATSフラグが渡された場合にのみ入力されます。

    \return 1 CTXが静的メモリを使用している場合にtrueとして返されます。
    \return 0 静的メモリを使用していない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param mem_stats 静的メモリの使用状況を含む構造体。

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    WOLFSSL_MEM_CONN_STATS mem_stats;
    ...
    ret = wolfSSL_is_static_memory(ssl, mem_stats);
    if (ret == 1) {
        // 静的メモリの場合のケースを処理
        // WOLFMEM_TRACK_STATSフラグがある場合、mem_stats内の要素を調査
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

    \brief この関数は、証明書ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。ファイルはfile引数によって提供されます。format引数はファイルのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMのいずれかです。適切な使用方法については、exampleを参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE 関数呼び出しが失敗した場合、考えられる原因には、ファイルが間違ったフォーマットである、または"format"引数を使用して間違ったフォーマットが指定されている、ファイルが存在しない、読み取れない、または破損している、メモリ不足の状態が発生している、ファイルのBase16デコードが失敗したことなどが含まれます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ
    \param file wolfSSL SSLコンテキストにロードされる証明書を含むファイルの名前へのポインタ。
    \param format - fileが指す証明書のフォーマット。可能なオプションはSSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_file(ctx, "./client-cert.pem",
                                     SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // 証明書ファイルのロードエラー
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

    \brief この関数は、秘密鍵ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。ファイルはfile引数によって提供されます。format引数はファイルのフォーマットタイプを指定します - SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。適切な使用方法については、exampleを参照してください。

    外部キーストアを使用していて秘密鍵を持っていない場合、代わりに公開鍵を提供し、署名を処理するための暗号コールバックを登録できます。これには、暗号コールバックまたはPKコールバックのいずれかでビルドできます。暗号コールバックを有効にするには、--enable-cryptocbまたはWOLF_CRYPTO_CBでビルドし、wc_CryptoCb_RegisterDeviceを使用して暗号コールバックを登録し、wolfSSL_CTX_SetDevIdを使用して関連するdevIdを設定します。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE ファイルが間違ったフォーマットである、または"format"引数を使用して間違ったフォーマットが指定されている。ファイルが存在しない、読み取れない、または破損している。メモリ不足の状態が発生している。ファイルのBase16デコードが失敗した。キーファイルが暗号化されているが、パスワードが提供されていない。

    \param none パラメータなし。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, "./server-key.pem",
                                    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // 鍵ファイルのロードエラー
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

    \brief この関数は、PEM形式のCA証明書ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。これらの証明書は信頼されたルート証明書として扱われ、SSLハンドシェイク中にピアから受信した証明書を検証するために使用されます。file引数によって提供されるルート証明書ファイルは、単一の証明書または複数の証明書を含むファイルである場合があります。
    同じファイルに複数のCA証明書が含まれている場合、wolfSSLはファイル内に提示された順序でそれらをロードします。path引数は、信頼されたルートCAの証明書を含むディレクトリの名前へのポインタです。fileの値がNULLでない場合、必要でなければpathをNULLとして指定できます。pathが指定され、ライブラリのビルド時にNO_WOLFSSL_DIRが定義されていない場合、wolfSSLは指定されたディレクトリにあるすべてのCA証明書をロードします。この関数はディレクトリ内のすべてのファイルをロードしようとします。この関数は、ヘッダー"-----BEGIN CERTIFICATE-----"を持つPEM形式のCERT_TYPEファイルを想定しています。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE ctxがNULLの場合、またはfileとpathの両方がNULLの場合に返されます。
    \return SSL_BAD_FILETYPE ファイルが間違ったフォーマットの場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return ASN_BEFORE_DATE_E 現在の日付がbefore dateより前の場合に返されます。
    \return ASN_AFTER_DATE_E 現在の日付がafter dateより後の場合に返されます。
    \return BUFFER_E チェーンバッファが受信バッファより大きい場合に返されます。
    \return BAD_PATH_ERROR pathを開こうとしたときにopendir()が失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param file PEM形式のCA証明書を含むファイルの名前へのポインタ。
    \param path PEM形式の証明書をロードするディレクトリの名前へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations(ctx, "./ca-cert.pem", NULL);
    if (ret != WOLFSSL_SUCCESS) {
    	// CA証明書のロードエラー
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
    \ingroup CertsKeys

    \brief この関数は、PEM形式のCA証明書ファイルをSSLコンテキスト(WOLFSSL_CTX)にロードします。これらの証明書は信頼されたルート証明書として扱われ、SSLハンドシェイク中にピアから受信した証明書を検証するために使用されます。file引数によって提供されるルート証明書ファイルは、単一の証明書または複数の証明書を含むファイルである場合があります。
    同じファイルに複数のCA証明書が含まれている場合、wolfSSLはファイル内に提示された順序でそれらをロードします。path引数は、信頼されたルートCAの証明書を含むディレクトリの名前へのポインタです。fileの値がNULLでない場合、必要でなければpathをNULLとして指定できます。pathが指定され、ライブラリのビルド時にNO_WOLFSSL_DIRが定義されていない場合、wolfSSLは指定されたディレクトリにあるすべてのCA証明書をロードします。この関数は、指定されたフラグに基づいてディレクトリ内のすべてのファイルをロードしようとします。この関数は、ヘッダー"-----BEGIN CERTIFICATE-----"を持つPEM形式のCERT_TYPEファイルを想定しています。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE ctxがNULLの場合、またはfileとpathの両方がNULLの場合に返されます。少なくとも1つの証明書が正常にロードされたが、1つ以上が失敗した場合もこれが返されます。理由についてはエラースタックを確認してください。
    \return SSL_BAD_FILETYPE ファイルが間違ったフォーマットの場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return BUFFER_E チェーンバッファが受信バッファより大きい場合に返されます。
    \return BAD_PATH_ERROR pathを開こうとしたときにopendir()が失敗した場合に返されます。    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param file PEM形式のCA証明書を含むファイル名へのポインタ。
    \param path PEM形式の証明書を読み込むディレクトリ名へのポインタ。
    \param flags 指定可能なマスク値: WOLFSSL_LOAD_FLAG_IGNORE_ERR、
    WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY、WOLFSSL_LOAD_FLAG_PEM_CA_ONLY

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations_ex(ctx, NULL, "./certs/external",
        WOLFSSL_LOAD_FLAG_PEM_CA_ONLY);
    if (ret != WOLFSSL_SUCCESS) {
        // CA証明書の読み込みエラー
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

    \brief この関数は、wolfSSL_CTX_load_system_CA_certsが呼び出されたときにwolfSSLがシステムCA証明書を検索するディレクトリを表す文字列の配列へのポインタを返します。証明書をアクセス可能なシステムディレクトリに保存しないシステム(Appleプラットフォームなど)では、この関数は常にNULLを返します。

    \return 成功時は有効なポインタ。
    \return 失敗時はNULLポインタ。

    \param num 文字列配列の長さが格納されるword32へのポインタ。

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

    \brief ほとんどのプラットフォーム(LinuxおよびWindowsを含む)において、この関数はOS依存のCA証明書ストアからWOLFSSL_CTXへCA証明書を読み込もうと試みます。読み込まれた証明書は信頼されます。

    Appleプラットフォーム(macOSを除く)では、証明書をシステムから取得できないため、wolfSSL証明書マネージャに読み込むことができません。これらのプラットフォームでは、この関数は、WOLFSSL_CTXにバインドされたTLS接続において、ユーザーによって読み込まれた証明書に対してピア証明書の信頼性を最初に認証できない場合に、ネイティブシステムの信頼APIを使用してピア証明書チェーンの信頼性を検証できるようにします。

    サポートおよびテストされているプラットフォームは、Linux(Debian、Ubuntu、
    Gentoo、Fedora、RHEL)、Windows 10/11、Android、macOS、およびiOSです。

    \return 成功時はWOLFSSL_SUCCESS。
    \return システムCA証明書が読み込まれなかった場合はWOLFSSL_BAD_PATH。
    \return その他の失敗タイプの場合はWOLFSSL_FAILURE(例: Windows証明書ストアが適切に閉じられなかった場合)。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_system_CA_certs(ctx,);
    if (ret != WOLFSSL_SUCCESS) {
        // システムCA証明書の読み込みエラー
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

    \brief この関数は、TLS/SSLハンドシェイクを実行する際にピアを検証するために使用する証明書を読み込みます。ハンドシェイク中に送信されるピア証明書は、利用可能な場合はSKIDを使用し、署名を使用して比較されます。これら2つが一致しない場合は、読み込まれたCAが使用されます。この機能はマクロWOLFSSL_TRUST_PEER_CERTを定義することで有効になります。適切な使用方法については、examplesを参照してください。

    \return 成功時はSSL_SUCCES。
    \return ctxがNULLの場合、またはfileとtypeの両方が無効な場合はSSL_FAILUREが返されます。
    \return ファイルの形式が間違っている場合はSSL_BAD_FILETYPEが返されます。
    \return ファイルが存在しない、読み取れない、または破損している場合はSSL_BAD_FILEが返されます。
    \return メモリ不足状態が発生した場合はMEMORY_Eが返されます。
    \return ファイルに対するBase16デコードが失敗した場合はASN_INPUT_Eが返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param file 証明書を含むファイル名へのポインタ。
    \param type 読み込まれる証明書のタイプ、すなわちSSL_FILETYPE_ASN1
    またはSSL_FILETYPE_PEM。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    ...

    ret = wolfSSL_CTX_trust_peer_cert(ctx, "./peer-cert.pem",
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        // 信頼されたピア証明書の読み込みエラー
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

    \brief この関数は、証明書チェーンをSSLコンテキスト(WOLFSSL_CTX)に読み込みます。証明書チェーンを含むファイルはfile引数によって提供され、PEM形式の証明書を含む必要があります。この関数は、MAX_CHAIN_DEPTH(デフォルト = 9、internal.hで定義)個までの証明書と、サブジェクト証明書を処理します。

    \return 成功時はSSL_SUCCESS。
    \return 関数呼び出しが失敗した場合はSSL_FAILURE。考えられる原因には、ファイルの形式が間違っている、または「format」引数を使用して間違った形式が指定されている、ファイルが存在しない、読み取れない、または破損している、メモリ不足状態が発生した、などがあります。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param file wolfSSL SSLコンテキストに読み込まれる証明書チェーンを含むファイルの名前へのポインタ。証明書はPEM形式である必要があります。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, "./cert-chain.pem");
    if (ret != SSL_SUCCESS) {
	    // 証明書ファイルの読み込みエラー
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

    \brief この関数は、SSL接続で使用されるプライベートRSA鍵をSSLコンテキスト(WOLFSSL_CTX)に読み込みます。この関数は、wolfSSLがOpenSSL互換レイヤーを有効にしてコンパイルされた場合(--enable-opensslExtra、#define OPENSSL_EXTRA)にのみ利用可能であり、より一般的に使用されるwolfSSL_CTX_use_PrivateKey_file()関数と同一です。file引数には、format引数で指定された形式のRSAプライベート鍵ファイルへのポインタが含まれます。

    \return 成功時はSSL_SUCCESS。
    \return 関数呼び出しが失敗した場合はSSL_FAILURE。考えられる原因には、入力鍵ファイルの形式が間違っている、または「format」引数を使用して間違った形式が指定されている、ファイルが存在しない、読み取れない、または破損している、メモリ不足状態が発生した、などがあります。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param file wolfSSL SSLコンテキストに読み込まれるRSAプライベート鍵を含むファイルの名前へのポインタ。形式はformat引数で指定されます。
    \param format file引数で指定されたRSAプライベート鍵のエンコーディングタイプ。指定可能な値には、SSL_FILETYPE_PEMおよびSSL_FILETYPE_ASN1が含まれます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_RSAPrivateKey_file(ctx, "./server-key.pem",
                                       SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // プライベート鍵ファイルの読み込みエラー
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

    \brief この関数は、有効なセッション(つまり、非NULLのセッションオブジェクト(ssl)が存在する場合)に対して許可される最大チェーン深度を返します。デフォルトは9です。

    \return WOLFSSL構造体がNULLでない場合はMAX_CHAIN_DEPTHが返されます。デフォルトでは値は9です。
    \return WOLFSSL構造体がNULLの場合はBAD_FUNC_ARGが返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    long sslDep = wolfSSL_get_verify_depth(ssl);

    if(sslDep > EXPECTED){
    	// 検証された深度は期待値よりも大きい
    } else {
    	// 検証された深度は期待値以下
    }
    \endcode

    \sa wolfSSL_CTX_get_verify_depth
*/
long wolfSSL_get_verify_depth(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、CTX構造体を使用して証明書チェーンの深度を取得します。

    \return CTX構造体がNULLでない場合はMAX_CHAIN_DEPTHが返されます。最大証明書チェーンピア深度の定数表現です。
    \return CTX構造体がNULLの場合はBAD_FUNC_ARGが返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_METHOD method; // プロトコルメソッド
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    long ret = wolfSSL_CTX_get_verify_depth(ctx);

    if(ret == EXPECTED){
    	//  期待値を取得しました
    } else {
    	//  予期しない深度を処理
    }
    \endcode

    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_get_verify_depth
*/
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief この関数は、証明書ファイルをSSLセッション(WOLFSSL構造体)に読み込みます。証明書ファイルはfile引数によって提供されます。format引数は、ファイルの形式タイプ(SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM)を指定します。

    \return 成功時はSSL_SUCCESS。
    \return 関数呼び出しが失敗した場合はSSL_FAILURE。考えられる原因には、ファイルの形式が間違っている、または「format」引数を使用して間違った形式が指定されている、ファイルが存在しない、読み取れない、または破損している、メモリ不足状態が発生した、ファイルに対するBase16デコードが失敗した、などがあります。

    \param ssl wolfSSL_new()で作成されたWOLFSSL構造体へのポインタ。
    \param file wolfSSL SSLセッションに読み込まれる証明書を含むファイルの名前へのポインタ。形式はformat引数で指定されます。
    \param format file引数で指定された証明書のエンコーディングタイプ。指定可能な値には、SSL_FILETYPE_PEMおよびSSL_FILETYPE_ASN1が含まれます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_certificate_file(ssl, "./client-cert.pem",
                                 SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// 証明書ファイルの読み込みエラー
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

    \brief この関数は、プライベート鍵ファイルをSSLセッション(WOLFSSL構造体)に読み込みます。鍵ファイルはfile引数によって提供されます。format引数は、ファイルの形式タイプ(SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM)を指定します。

    外部鍵ストアを使用していてプライベート鍵を持っていない場合は、代わりに公開鍵を提供し、署名を処理するための暗号コールバックを登録することができます。これには、暗号コールバックまたはPKコールバックのいずれかを有効にしてビルドします。暗号コールバックを有効にするには、--enable-cryptocbまたはWOLF_CRYPTO_CBを使用し、wc_CryptoCb_RegisterDeviceを使用して暗号コールバックを登録し、wolfSSL_SetDevIdを使用して関連するdevIdを設定します。

    \return 成功時はSSL_SUCCESS。
    \return 関数呼び出しが失敗した場合はSSL_FAILURE。考えられる原因には、ファイルの形式が間違っている、または「format」引数を使用して間違った形式が指定されている、ファイルが存在しない、読み取れない、または破損している、メモリ不足状態が発生した、ファイルに対するBase16デコードが失敗した、鍵ファイルが暗号化されているがパスワードが提供されていない、などがあります。

    \param ssl wolfSSL_new()で作成されたWOLFSSL構造体へのポインタ。
    \param file wolfSSL SSLセッションに読み込まれる鍵ファイルを含むファイルの名前へのポインタ。形式はformat引数で指定されます。
    \param format file引数で指定された鍵のエンコーディングタイプ。指定可能な値には、SSL_FILETYPE_PEMおよびSSL_FILETYPE_ASN1が含まれます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_PrivateKey_file(ssl, "./server-key.pem",
                                SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // 鍵ファイルの読み込みエラー
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
    \brief この関数は、証明書のチェーンをSSLセッション(WOLFSSL構造体)にロードします。証明書チェーンを含むファイルはfile引数で指定され、PEM形式の証明書を含んでいる必要があります。この関数は、MAX_CHAIN_DEPTH(デフォルト = 9、internal.hで定義)個までの証明書と、サブジェクト証明書を処理します。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE 関数呼び出しが失敗した場合、考えられる原因は次のとおりです:ファイルの形式が間違っている、または"format"引数で与えられた形式が間違っている、ファイルが存在しない、読み取れない、または破損している、メモリ不足の状態が発生した

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param file wolfSSL SSLセッションにロードする証明書のチェーンを含むファイルの名前へのポインタ。証明書はPEM形式でなければなりません。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ctx;
    ...
    ret = wolfSSL_use_certificate_chain_file(ssl, "./cert-chain.pem");
    if (ret != SSL_SUCCESS) {
    	// 証明書ファイルのロードエラー
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

    \brief この関数は、SSL接続で使用されるプライベートRSA鍵をSSLセッション(WOLFSSL構造体)にロードします。この関数は、wolfSSLがOpenSSL互換レイヤーを有効にしてコンパイルされている場合(--enable-opensslExtra、#define OPENSSL_EXTRA)にのみ利用可能であり、より一般的に使用されるwolfSSL_use_PrivateKey_file()関数と同一です。file引数は、formatで指定された形式のRSAプライベート鍵ファイルへのポインタを含みます。

    \return SSL_SUCCESS 成功時
    \return SSL_FAILURE 関数呼び出しが失敗した場合、考えられる原因は次のとおりです:入力鍵ファイルの形式が間違っている、または"format"引数で与えられた形式が間違っている、ファイルが存在しない、読み取れない、または破損している、メモリ不足の状態が発生した

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ
    \param file wolfSSL SSLセッションにロードするRSAプライベート鍵を含むファイルの名前へのポインタ、形式はformatで指定されます。
    \param format fileで指定されたRSAプライベート鍵のエンコーディングタイプ。指定可能な値はSSL_FILETYPE_PEMとSSL_FILETYPE_ASN1です。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_RSAPrivateKey_file(ssl, "./server-key.pem",
                                   SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // プライベート鍵ファイルのロードエラー
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

    \brief この関数はwolfSSL_CTX_load_verify_locationsに似ていますが、DER形式のCAファイルをSSLコンテキスト(WOLFSSL_CTX)にロードできます。PEM形式のCAファイルをロードするためにも使用できます。これらの証明書は信頼されたルート証明書として扱われ、SSLハンドシェイク中にピアから受信した証明書を検証するために使用されます。file引数で指定されるルート証明書ファイルは、単一の証明書または複数の証明書を含むファイルである可能性があります。複数のCA証明書が同じファイルに含まれている場合、wolfSSLはファイル内で提示された順序でそれらをロードします。format引数は、証明書の形式がSSL_FILETYPE_PEMまたはSSL_FILETYPE_ASN1(DER)のいずれかであることを指定します。wolfSSL_CTX_load_verify_locationsとは異なり、この関数は指定されたディレクトリパスからのCA証明書のロードを許可しません。この関数は、wolfSSLライブラリがWOLFSSL_DER_LOADを定義してコンパイルされている場合にのみ利用可能です。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE 失敗時。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ
    \param file wolfSSL SSLコンテキストにロードするCA証明書を含むファイルの名前へのポインタ、形式はformatで指定されます。
    \param format fileで指定された証明書のエンコーディングタイプ。指定可能な値はSSL_FILETYPE_PEMとSSL_FILETYPE_ASN1です。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_der_load_verify_locations(ctx, "./ca-cert.der",
                                          SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
	    // CA証明書のロードエラー
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

    \brief この関数は、入力として希望するSSL/TLSプロトコルメソッドを取り、新しいSSLコンテキストを作成します。

    \return pointer 成功した場合、呼び出しは新しく作成されたWOLFSSL_CTXへのポインタを返します。
    \return NULL 失敗時。

    \param method SSLコンテキストに使用する希望のWOLFSSL_METHODへのポインタ。これは、SSL/TLS/DTLSプロトコルレベルを指定するためのwolfSSLvXX_XXXX_method()関数のいずれかを使用して作成されます。

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    WOLFSSL_METHOD* method = 0;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
    	// メソッドを取得できません
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
    	// コンテキストの作成に失敗しました
    }
    \endcode

    \sa wolfSSL_new
*/
WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);

/*!
    \ingroup Setup

    \brief この関数は、既に作成されたSSLコンテキストを入力として取り、新しいSSLセッションを作成します。

    \return ＊ 成功した場合、呼び出しは新しく作成されたwolfSSL構造体へのポインタを返します。
    \return NULL 失敗時。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL*     ssl = NULL;
    WOLFSSL_CTX* ctx = 0;

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
	    // コンテキストの作成に失敗しました
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
	    // SSLオブジェクトの作成に失敗しました
    }
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief この関数は、ファイルディスクリプタ(fd)をSSL接続の入出力機能として割り当てます。通常、これはソケットファイルディスクリプタになります。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 失敗時。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param fd SSL/TLS接続で使用するファイルディスクリプタ。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
    	// SSLファイルディスクリプタの設定に失敗しました
    }
    \endcode

    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
*/
int  wolfSSL_set_fd(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief この関数は、ファイルディスクリプタ(fd)をSSL接続の入出力機能として割り当てます。通常、これはソケットファイルディスクリプタになります。これは、ソケットが接続されていることをマークするため、DTLS固有のAPIです。このfdに対するrecvfromおよびsendto呼び出しは、addrおよびaddr_lenパラメータがNULLに設定されます。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 失敗時。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param fd SSL/TLS接続で使用するファイルディスクリプタ。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    if (connect(sockfd, peer_addr, peer_addr_len) != 0) {
        // 接続エラーを処理
    }
    ...
    ret = wolfSSL_set_dtls_fd_connected(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        // SSLファイルディスクリプタの設定に失敗しました
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

    \brief 正しく処理および検証されたDTLSクライアントhelloに対するコールバックを設定できます。クッキー交換メカニズム(DTLS 1.2のHelloVerifyRequestまたはクッキー拡張を伴うDTLS 1.3のHelloRetryRequest)を使用する場合、このコールバックはクッキー交換が成功した後に呼び出されます。これは、1つのWOLFSSLオブジェクトを新しい接続のリスナーとして使用し、ClientHelloが検証された後(クッキー交換を通じて、またはClientHelloが正しい形式であるかをチェックするだけで)にWOLFSSLオブジェクトを分離できるようにするのに役立ちます。
           DTLS 1.2:
           https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
           DTLS 1.3:
           https://www.rfc-editor.org/rfc/rfc8446#section-4.2.2

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 失敗時。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param fd SSL/TLS接続で使用するファイルディスクリプタ。

    _Example_
    \code

    // 接続を検証したときに呼び出されます
    static int chGoodCb(WOLFSSL* ssl, void* arg)
    {
        // ピアとファイルディスクリプタを設定

    }

    if (wolfDTLS_SetChGoodCb(ssl, chGoodCb, NULL) != WOLFSSL_SUCCESS) {
         // コールバック設定エラー
    }
    \endcode

    \sa wolfSSL_set_dtls_fd_connected
*/
int wolfDTLS_SetChGoodCb(WOLFSSL* ssl, ClientHelloGoodCb cb, void* user_ctx);

/*!
    \ingroup IO

    \brief 渡された優先度レベルでの暗号の名前を取得します。

    \return string 成功
    \return 0 優先度が範囲外または無効です。

    \param priority 暗号の優先度レベルを表す整数。

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

    \brief この関数は、wolfSSLで有効になっている暗号を取得します。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG bufパラメータがNULLまたはlen引数がゼロ以下の場合に返されます。
    \return BUFFER_E バッファが十分に大きくなくオーバーフローする場合に返されます。

    \param buf バッファを表すcharポインタ。
    \param len バッファの長さ。

    _Example_
    \code
    static void ShowCiphers(void){
        char* ciphers;
        int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

	    if(ret == SSL_SUCCESS){
	    	printf("%s\n", ciphers);
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

    \brief この関数は、引数をwolfSSL_get_cipher_name_internalに渡すことによって、DHE-RSA形式で暗号名を取得します。

    \return string この関数は、マッチした暗号スイートの文字列表現を返します。
    \return NULL エラーまたは暗号が見つかりません。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    char* cipher = wolfSSL_get_cipher_name(ssl);

    if(cipher == NULL){
	    // 暗号スイートがマッチしませんでした
    } else {
	    // 暗号スイートがマッチしました
	    printf("%s\n", cipherS);
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
*/
const char* wolfSSL_get_cipher_name(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数は、SSL接続の入力機能として使用される読み取りファイル記述子(fd)を返します。通常、これはソケットファイル記述子になります。
    \return fd 成功した場合、この関数はSSLセッションファイルディスクリプタを返します。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_fd(ssl);
    ...
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_read_fd
    \sa wolfSSL_set_write_fd
*/
int  wolfSSL_get_fd(const WOLFSSL*);

/*!
    \ingroup IO

    \brief この関数は、SSL接続の出力機能として使用される書き込みファイルディスクリプタ(fd)を返します。通常はソケットファイルディスクリプタになります。

    \return fd 成功した場合、この関数はSSLセッションファイルディスクリプタを返します。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_wfd(ssl);
    ...
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_read_fd
    \sa wolfSSL_set_write_fd
*/
int  wolfSSL_get_wfd(const WOLFSSL*);

/*!
    \ingroup Setup

    \brief この関数は、WOLFSSLオブジェクトに対して、下層のI/Oがノンブロッキングであることを通知します。アプリケーションがWOLFSSLオブジェクトを作成した後、それをノンブロッキングソケットと共に使用する場合は、wolfSSL_set_using_nonblock()を呼び出してください。これにより、WOLFSSLオブジェクトは、EWOULDBLOCKを受け取ることがタイムアウトではなく、recvfrom呼び出しがブロックすることを意味すると認識できます。

    \return none 戻り値はありません。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param nonblock WOLFSSLオブジェクトのノンブロッキングフラグを設定するための値。ノンブロッキングを指定する場合は1を、そうでない場合は0を使用してください。

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

    \brief この関数により、アプリケーションはwolfSSLがノンブロッキングI/Oを使用しているかどうかを判定できます。wolfSSLがノンブロッキングI/Oを使用している場合、この関数は1を返し、それ以外の場合は0を返します。アプリケーションがWOLFSSLオブジェクトを作成した後、それをノンブロッキングソケットと共に使用する場合は、wolfSSL_set_using_nonblock()を呼び出してください。これにより、WOLFSSLオブジェクトは、EWOULDBLOCKを受け取ることがタイムアウトではなく、recvfrom呼び出しがブロックすることを意味すると認識できます。

    \return 0 下層のI/Oがブロッキングです。
    \return 1 下層のI/Oがノンブロッキングです。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_get_using_nonblock(ssl);
    if (ret == 1) {
    	// 下層のI/Oはノンブロッキング
    }
    ...
    \endcode

    \sa wolfSSL_set_session
*/
int  wolfSSL_get_using_nonblock(WOLFSSL*);

/*!
    \ingroup IO

    \brief この関数は、バッファdataからszバイトをSSL接続sslに書き込みます。必要に応じて、wolfSSL_connect()またはwolfSSL_accept()によってハンドシェイクがまだ実行されていない場合、wolfSSL_write()はSSL/TLSセッションをネゴシエートします。(D)TLSv1.3を使用していてearly data機能がコンパイルされている場合、この関数はデータ送信が可能になるまでハンドシェイクを進めます。次のwolfSSL_Connect()、wolfSSL_Accept()、wolfSSL_read()の呼び出しでハンドシェイクが完了します。wolfSSL_write()は、ブロッキングとノンブロッキングの両方のI/Oで動作します。下層のI/Oがノンブロッキングの場合、wolfSSL_write()は、下層のI/OがwolfSSL_write()を継続するために必要な要求を満たせなくなった時点で返されます。この場合、wolfSSL_get_error()を呼び出すと、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかが返されます。呼び出し側プロセスは、下層のI/Oの準備ができたら、wolfSSL_write()の呼び出しを繰り返す必要があります。下層のI/Oがブロッキングの場合、wolfSSL_write()は、サイズszのバッファデータが完全に書き込まれるか、エラーが発生するまで返されません。

    \return ＞0 成功時に書き込まれたバイト数。
    \return 0 失敗時に返されます。具体的なエラーコードについては、wolfSSL_get_error()を呼び出してください。
    \return SSL_FATAL_ERROR エラーが発生した場合、またはノンブロッキングソケットを使用している場合にSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーを受け取り、アプリケーションがwolfSSL_write()を再度呼び出す必要がある場合に返されます。具体的なエラーコードを取得するには、wolfSSL_get_error()を使用してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param data ピアに送信されるデータバッファ。
    \param sz ピアに送信するデータ(data)のサイズ(バイト単位)。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = "hello wolfssl!";
    int msgSz = (int)strlen(msg);
    int flags;
    int ret;
    ...

    ret = wolfSSL_write(ssl, msg, msgSz);
    if (ret <= 0) {
    	// wolfSSL_write()が失敗、wolfSSL_get_error()を呼び出す
    }
    \endcode

    \sa wolfSSL_send
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_write(WOLFSSL* ssl, const void* data, int sz);

/*!
    \ingroup IO

    \brief この関数は、SSLセッション(ssl)の内部読み取りバッファからszバイトをバッファdataに読み込みます。読み取られたバイトは内部受信バッファから削除されます。必要に応じて、wolfSSL_connect()またはwolfSSL_accept()によってハンドシェイクがまだ実行されていない場合、wolfSSL_read()はSSL/TLSセッションをネゴシエートします。SSL/TLSプロトコルは、最大サイズが16kBのSSLレコードを使用します(最大レコードサイズは、<wolfssl_root>/wolfssl/internal.h内のMAX_RECORD_SIZE定義で制御できます)。そのため、wolfSSLは、レコードを処理および復号できるようになる前に、SSLレコード全体を内部的に読み取る必要があります。このため、wolfSSL_read()の呼び出しは、呼び出し時に復号された最大バッファサイズのみを返すことができます。内部wolfSSL受信バッファには、まだ復号されていない追加データが待機している可能性があり、これは次のwolfSSL_read()呼び出しで取得および復号されます。szが内部読み取りバッファ内のバイト数よりも大きい場合、SSL_read()は内部読み取りバッファ内で利用可能なバイトを返します。内部読み取りバッファにまだバイトがバッファリングされていない場合、wolfSSL_read()の呼び出しは次のレコードの処理をトリガします。

    \return ＞0 成功時に読み取られたバイト数。
    \return 0 失敗時に返されます。これは、クリーンシャットダウン(close notifyアラート)またはピアが接続を閉じたことが原因である可能性があります。具体的なエラーコードについては、wolfSSL_get_error()を呼び出してください。
    \return SSL_FATAL_ERROR エラーが発生した場合、またはノンブロッキングソケットを使用している場合にSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーを受け取り、アプリケーションがwolfSSL_read()を再度呼び出す必要がある場合に返されます。具体的なエラーコードを取得するには、wolfSSL_get_error()を使用してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param data wolfSSL_read()が読み取ったデータを格納するバッファ。
    \param sz dataに読み込むバイト数。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
    	// バッファ"reply"に"input"バイトが返された
    }

    wolfSSL_read()のより完全な例については、wolfSSLの例(client、server、echoclient、echoserver)を参照してください。
    \endcode

    \sa wolfSSL_recv
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
int  wolfSSL_read(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO

    \brief この関数は、SSLセッション(ssl)の内部読み取りバッファからszバイトをバッファdataにコピーします。この関数は、内部SSLセッション受信バッファ内のデータが削除または変更されない点を除いて、wolfSSL_read()と同じです。wolfSSL_read()と同様に、必要に応じて、wolfSSL_connect()またはwolfSSL_accept()によってハンドシェイクがまだ実行されていない場合、wolfSSL_peek()はSSL/TLSセッションをネゴシエートします。SSL/TLSプロトコルは、最大サイズが16kBのSSLレコードを使用します(最大レコードサイズは、<wolfssl_root>/wolfssl/internal.h内のMAX_RECORD_SIZE定義で制御できます)。そのため、wolfSSLは、レコードを処理および復号できるようになる前に、SSLレコード全体を内部的に読み取る必要があります。このため、wolfSSL_peek()の呼び出しは、呼び出し時に復号された最大バッファサイズのみを返すことができます。内部wolfSSL受信バッファには、まだ復号されていない追加データが待機している可能性があり、これは次のwolfSSL_peek()またはwolfSSL_read()呼び出しで取得および復号されます。szが内部読み取りバッファ内のバイト数よりも大きい場合、SSL_peek()は内部読み取りバッファ内で利用可能なバイトを返します。内部読み取りバッファにまだバイトがバッファリングされていない場合、wolfSSL_peek()の呼び出しは次のレコードの処理をトリガします。

    \return ＞0 成功時に読み取られたバイト数。
    \return 0 失敗時に返されます。これは、クリーンシャットダウン(close notifyアラート)またはピアが接続を閉じたことが原因である可能性があります。具体的なエラーコードについては、wolfSSL_get_error()を呼び出してください。
    \return SSL_FATAL_ERROR エラーが発生した場合、またはノンブロッキングソケットを使用している場合にSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーを受け取り、アプリケーションがwolfSSL_peek()を再度呼び出す必要がある場合に返されます。具体的なエラーコードを取得するには、wolfSSL_get_error()を使用してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param data wolfSSL_peek()が読み取ったデータを格納するバッファ。
    \param sz dataに読み込むバイト数。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_peek(ssl, reply, sizeof(reply));
    if (input > 0) {
	    // バッファ"reply"に"input"バイトが返された
    }
    \endcode

    \sa wolfSSL_read
*/
int  wolfSSL_peek(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO

    \brief この関数はサーバ側で呼び出され、SSLクライアントがSSL/TLSハンドシェイクを開始するのを待機します。この関数が呼び出されるとき、下層の通信チャネルはすでに設定されています。wolfSSL_accept()は、ブロッキングとノンブロッキングの両方のI/Oで動作します。下層のI/Oがノンブロッキングの場合、wolfSSL_accept()は、下層のI/OがwolfSSL_acceptがハンドシェイクを継続するために必要な要求を満たせなくなった時点で返されます。この場合、wolfSSL_get_error()を呼び出すと、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかが返されます。呼び出し側プロセスは、データの読み取りが可能になったらwolfSSL_accept()の呼び出しを繰り返す必要があり、wolfSSLは中断した箇所から再開します。ノンブロッキングソケットを使用する場合、何もする必要はありませんが、select()を使用して必要な条件を確認できます。下層のI/Oがブロッキングの場合、wolfSSL_accept()は、ハンドシェイクが完了するか、エラーが発生するまで返されません。

    \return SSL_SUCCESS 成功時。
    \return SSL_FATAL_ERROR エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出してください。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

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
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
int  wolfSSL_accept(WOLFSSL*);

/*!
    \ingroup IO

    \brief この関数はサーバ側で呼び出され、SSLクライアントがDTLSハンドシェイクを開始するのをステートレスに待機します。

    \return WOLFSSL_SUCCESS 有効なクッキーを含むClientHelloが受信されました。wolfSSL_accept()で接続を続行できます。
    \return WOLFSSL_FAILURE I/O層がWANT_READを返しました。これは、読み取るデータがなくノンブロッキングソケットを使用しているか、クッキーリクエストを送信して応答を待っているためです。ユーザは、I/O層でデータが利用可能になった後、wolfDTLS_accept_statelessを再度呼び出す必要があります。
    \return WOLFSSL_FATAL_ERROR 致命的なエラーが発生しました。sslオブジェクトを解放して再割り当てしてから続行する必要があります。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    ...
    do {
        ret = wolfDTLS_accept_stateless(ssl);
        if (ret == WOLFSSL_FATAL_ERROR)
            // wolfSSL_free()とwolfSSL_new()でsslオブジェクトを再割り当て
    } while (ret != WOLFSSL_SUCCESS);
    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_accept
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
int  wolfDTLS_accept_stateless(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、割り当てられたWOLFSSL_CTXオブジェクトを解放します。この関数はCTX参照カウントをデクリメントし、参照カウントが0になった場合にのみコンテキストを解放します。

    \return none 戻り値はありません。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

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

    \brief この関数は、割り当てられたwolfSSLオブジェクトを解放します。

    \return none 戻り値はありません。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。

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

    \brief この関数は、SSLセッションsslを使用してアクティブなSSL/TLS接続をシャットダウンします。この関数は、ピアに「close notify」アラートを送信しようと試みます。呼び出し側のアプリケーションは、ピアからの応答として「close notify」アラートが送信されるのを待つか、wolfSSL_shutdown()を直接呼び出した後に基盤となる接続をシャットダウンするか(リソースを節約するため)を選択できます。TLS仕様では、どちらのオプションも許可されています。基盤となる接続を将来再び使用する場合は、ピア間の同期を維持するために、完全な双方向シャットダウン手順を実行する必要があります。wolfSSL_shutdown()は、ブロッキングI/OとノンブロッキングI/Oの両方で動作します。基盤となるI/Oがノンブロッキングの場合、基盤となるI/OがwolfSSL_shutdown()の継続に必要な要求を満たせなかった場合、wolfSSL_shutdown()はエラーを返します。この場合、wolfSSL_get_error()を呼び出すと、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかが返されます。呼び出し側プロセスは、基盤となるI/Oの準備ができたときに、wolfSSL_shutdown()の呼び出しを繰り返す必要があります。

    \return SSL_SUCCESSが成功時に返されます。
    \return SSL_SHUTDOWN_NOT_DONEは、シャットダウンが完了していない場合に返され、関数を再度呼び出す必要があります。
    \return SSL_FATAL_ERRORは、失敗時に返されます。より具体的なエラーコードについては、wolfSSL_get_error()を呼び出してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_shutdown(ssl);
    if (ret != 0) {
	    // SSL接続のシャットダウンに失敗しました
    }
    \endcode

    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
int  wolfSSL_shutdown(WOLFSSL*);

/*!
    \ingroup IO

    \brief この関数は、指定されたフラグを使用して、バッファdataからszバイトをSSL接続sslに書き込みます。必要に応じて、wolfSSL_connect()またはwolfSSL_accept()によってハンドシェイクがまだ実行されていない場合、wolfSSL_send()はSSL/TLSセッションをネゴシエートします。wolfSSL_send()は、ブロッキングI/OとノンブロッキングI/Oの両方で動作します。基盤となるI/Oがノンブロッキングの場合、基盤となるI/OがwolfSSL_sendの継続に必要な要求を満たせなかった場合、wolfSSL_send()は戻ります。この場合、wolfSSL_get_error()を呼び出すと、SSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかが返されます。呼び出し側プロセスは、基盤となるI/Oの準備ができたときに、wolfSSL_send()の呼び出しを繰り返す必要があります。基盤となるI/Oがブロッキングの場合、wolfSSL_send()は、サイズszのバッファdataが完全に書き込まれるか、エラーが発生するまで戻りません。

    \return ＞0は、成功時に書き込まれたバイト数です。
    \return 0は、失敗時に返されます。具体的なエラーコードについては、wolfSSL_get_error()を呼び出してください。
    \return SSL_FATAL_ERRORは、エラーが発生した場合、またはノンブロッキングソケットを使用している場合にSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが発生し、アプリケーションがwolfSSL_send()を再度呼び出す必要がある場合に返されます。具体的なエラーコードを取得するには、wolfSSL_get_error()を使用してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param data ピアに送信するデータバッファ。
    \param sz ピアに送信するデータのサイズ(バイト単位)。
    \param flags 基盤となる送信操作に使用する送信フラグ。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = "hello wolfssl!";
    int msgSz = (int)strlen(msg);
    int flags = ... ;
    ...

    input = wolfSSL_send(ssl, msg, msgSz, flags);
    if (input != msgSz) {
    	// wolfSSL_send()が失敗しました
    }
    \endcode

    \sa wolfSSL_write
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags);

/*!
    \ingroup IO

    \brief この関数は、指定されたフラグを使用して、SSLセッション(ssl)の内部読み取りバッファからszバイトをバッファdataに読み込みます。読み取られたバイトは、内部受信バッファから削除されます。この関数は、基盤となる読み取り操作のrecvフラグをアプリケーションが設定できる点を除いて、wolfSSL_read()と同じです。必要に応じて、wolfSSL_connect()またはwolfSSL_accept()によってハンドシェイクがまだ実行されていない場合、wolfSSL_recv()はSSL/TLSセッションをネゴシエートします。SSL/TLSプロトコルは、最大サイズ16kBのSSLレコードを使用します(最大レコードサイズは、<wolfssl_root>/wolfssl/internal.hのMAX_RECORD_SIZE定義で制御できます)。そのため、wolfSSLは、レコードを処理および復号する前に、内部でSSLレコード全体を読み取る必要があります。このため、wolfSSL_recv()の呼び出しは、呼び出し時に復号された最大バッファサイズのみを返すことができます。まだ復号されていない追加データが内部wolfSSL受信バッファで待機している可能性があり、次回のwolfSSL_recv()呼び出しで取得および復号されます。szが内部読み取りバッファのバイト数より大きい場合、SSL_recv()は内部読み取りバッファで利用可能なバイトを返します。内部読み取りバッファにまだバッファリングされているバイトがない場合、wolfSSL_recv()の呼び出しは次のレコードの処理をトリガーします。

    \return ＞0は、成功時に読み取られたバイト数です。
    \return 0は、失敗時に返されます。これは、クリーンな(close notifyアラート)シャットダウンによって引き起こされる場合もあれば、単にピアが接続を閉じた場合もあります。具体的なエラーコードについては、wolfSSL_get_error()を呼び出してください。
    \return SSL_FATAL_ERRORは、エラーが発生した場合、またはノンブロッキングソケットを使用している場合にSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーが発生し、アプリケーションがwolfSSL_recv()を再度呼び出す必要がある場合に返されます。具体的なエラーコードを取得するには、wolfSSL_get_error()を使用してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param data wolfSSL_recv()が読み取ったデータを配置するバッファ。
    \param sz dataに読み込むバイト数。
    \param flags 基盤となる受信操作に使用する受信フラグ。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    int flags = ... ;
    ...

    input = wolfSSL_recv(ssl, reply, sizeof(reply), flags);
    if (input > 0) {
    	// バッファ"reply"に"input"バイトが返されました
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

    \brief この関数は、前回のAPI関数呼び出し(wolfSSL_connect、wolfSSL_accept、wolfSSL_read、wolfSSL_write等)がエラーリターンコード(SSL_FAILURE)になった理由を説明する一意のエラーコードを返します。前回の関数の戻り値は、retを通じてwolfSSL_get_errorに渡されます。wolfSSL_get_errorが呼び出されて一意のエラーコードを返した後、wolfSSL_ERR_error_string()を呼び出して、人間が読めるエラー文字列を取得できます。詳細については、wolfSSL_ERR_error_string()を参照してください。

    \return 正常に完了した場合、この関数は前回のAPI関数が失敗した理由を説明する一意のエラーコードを返します。
    \return SSL_ERROR_NONEは、ret > 0の場合に返されます。ret <= 0の場合、前回のAPIがエラーコードを返したように見えても実際にはエラーが発生していなかった場合に、この値が返されることがあります。例えば、szパラメータがゼロのwolfSSL_read()を呼び出した場合です。wolfSSL_read()からの0の戻り値は通常エラーを示しますが、この場合はエラーは発生していません。その後wolfSSL_get_error()を呼び出すと、SSL_ERROR_NONEが返されます。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param ret エラーリターンコードになった前回の関数の戻り値。

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf("err = %d, %s\n", err, buffer);
    \endcode

    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
int  wolfSSL_get_error(WOLFSSL* ssl, int ret);

/*!
    \ingroup IO

    \brief この関数はアラート履歴を取得します。

    \return SSL_SUCCESSは、関数が正常に完了したときに返されます。アラート履歴があってもなくても、いずれの場合も戻り値はSSL_SUCCESSです。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param h WOLFSSL構造体のalert_historyメンバーの値を保持するWOLFSSL_ALERT_HISTORY構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_ALERT_HISTORY* h;
    ...
    wolfSSL_get_alert_history(ssl, h);
    // hにssl->alert_historyの内容のコピーが格納されました
    \endcode

    \sa wolfSSL_get_error
*/
int  wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h);

/*!
    \ingroup Setup

    \brief この関数は、SSLオブジェクトsslがSSL/TLS接続を確立するために使用されるときに使用されるセッションを設定します。セッション再開の場合、セッションオブジェクトでwolfSSL_shutdown()を呼び出す前に、アプリケーションはwolfSSL_get1_session()を呼び出してオブジェクトからセッションIDを保存する必要があります。これはセッションへのポインタを返します。後で、アプリケーションは新しいWOLFSSLオブジェクトを作成し、wolfSSL_set_session()を使用して保存されたセッションを割り当てる必要があります。この時点で、アプリケーションはwolfSSL_connect()を呼び出すことができ、wolfSSLはセッションの再開を試みます。wolfSSLサーバーコードは、デフォルトでセッション再開を許可します。wolfSSL_get1_session()によって返されたオブジェクトは、アプリケーションが使用を終えた後、wolfSSL_SESSION_free()を呼び出して解放する必要があります。

    \return SSL_SUCCESSは、セッションの設定に成功した場合に返されます。
    \return SSL_FAILUREは、失敗時に返されます。これは、セッションキャッシュが無効になっている場合、またはセッションがタイムアウトした場合に発生する可能性があります。

    \return OPENSSL_EXTRAとWOLFSSL_ERROR_CODE_OPENSSLが定義されている場合、セッションがタイムアウトしてもSSL_SUCCESSが返されます。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param session sslのセッションを設定するために使用されるWOLFSSL_SESSIONへのポインタ。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get1_session(ssl);
    if (session == NULL) {
        // sslオブジェクトからセッションオブジェクトの取得に失敗しました
    }
    ...
    ret = wolfSSL_set_session(ssl, session);
    if (ret != SSL_SUCCESS) {
    	// SSLセッションの設定に失敗しました
    }
    wolfSSL_SESSION_free(session);
    ...
    \endcode

    \sa wolfSSL_get1_session
*/
int        wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session);

/*!
    \ingroup IO

    \brief NO_SESSION_CACHE_REFが定義されている場合、この関数はsslで使用されている現在のセッション(WOLFSSL_SESSION)へのポインタを返します。この関数は、WOLFSSL_SESSIONオブジェクトへの非永続的なポインタを返します。返されたポインタは、wolfSSL_freeが呼び出されたときに解放されます。この呼び出しは、現在のセッションを検査または変更するためにのみ使用する必要があります。セッション再開には、wolfSSL_get1_session()を使用することをお勧めします。後方互換性のため、NO_SESSION_CACHE_REFが定義されていない場合、この関数はローカルキャッシュに格納されている永続的なセッションオブジェクトポインタを返します。キャッシュサイズは有限であり、アプリケーションがwolfSSL_set_session()を呼び出すまでに、別のssl接続によってセッションオブジェクトが上書きされるリスクがあります。アプリケーションでNO_SESSION_CACHE_REFを定義し、セッション再開にwolfSSL_get1_session()を使用することをお勧めします。

    \return pointer 呼び出しが成功した場合、現在のSSLセッションオブジェクトへのポインタを返します。
    \return NULLは、sslがNULLの場合、SSLセッションキャッシュが無効になっている場合、wolfSSLがセッションIDを利用できない場合、またはミューテックス関数が失敗した場合に返されます。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get_session(ssl);
    if (session == NULL) {
	    // セッションポインタの取得に失敗しました
    }
    ...
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数は、期限切れのセッションをセッションキャッシュからフラッシュします。時刻tmは、時刻比較に使用されます。wolfSSLは現在セッションに静的テーブルを使用しているため、フラッシュは不要です。そのため、この関数は現在スタブにすぎません。この関数は、wolfSSLがOpenSSL互換レイヤーでコンパイルされている場合、OpenSSL互換性(SSL_flush_sessions)を提供します。

    \return none 戻り値はありません。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param tm セッション有効期限比較に使用される時刻。

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

    \brief この関数は、クライアントセッションをサーバーIDに関連付けます。newSessionフラグがオンの場合、既存のセッションは再利用されません。

    \return SSL_SUCCESSは、関数がエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARGは、WOLFSSL構造体またはidパラメータがNULLの場合、またはlenが0より大きくない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param id WOLFSSL_SESSION構造体のserverIDメンバーにコピーされる定数バイトポインタ。
    \param len セッションidパラメータの長さを表すint型。
    \param newSession セッションを再利用するかどうかを示すフラグを表すint型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    const byte id[MAX_SIZE];  // または動的にスペースを作成
    int len = 0; // 長さを初期化
    int newSession = 0; // 許可するフラグ
    …
    int ret = wolfSSL_SetServerID(ssl, id, len, newSession);

    if (ret == WOLFSSL_SUCCESS) {
	    // IDが正常に設定されました
    }
    \endcode

    \sa wolfSSL_set_session
*/
int        wolfSSL_SetServerID(WOLFSSL* ssl, const unsigned char* id,
                                         int len, int newSession);

/*!
    \ingroup IO

    \brief この関数は、WOLFSSL構造体のセッションインデックスを取得します。

    \return int この関数は、WOLFSSL構造体内のsessionIndexを表すint型を返します。
    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int sesIdx = wolfSSL_GetSessionIndex(ssl);

    if(sesIdx < 0 || sesIdx > sizeof(ssl->sessionIndex)/sizeof(int)){
    	// インデックス番号が範囲外であり、何かが正しくありません。
    }
    \endcode

    \sa wolfSSL_GetSessionAtIndex
*/
int wolfSSL_GetSessionIndex(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数はセッションキャッシュの指定されたインデックスにあるセッションを取得し、メモリにコピーします。WOLFSSL_SESSION構造体はセッション情報を保持します。

    \return SSL_SUCCESS 関数が正常に実行され、エラーが発生しなかった場合に返されます。
    \return BAD_MUTEX_E mutexのアンロックまたはロックエラーがあった場合に返されます。
    \return SSL_FAILURE 関数が正常に実行されなかった場合に返されます。

    \param idx セッションインデックスを表すint型。
    \param session WOLFSSL_SESSION構造体へのポインタ。

    _Example_
    \code
    int idx; // セッションを特定するインデックス。
    WOLFSSL_SESSION* session;  // コピー先のバッファ。
    ...
    if(wolfSSL_GetSessionAtIndex(idx, session) != SSL_SUCCESS){
    	// 失敗ケース。
    }
    \endcode

    \sa UnLockMutex
    \sa LockMutex
    \sa wolfSSL_GetSessionIndex
*/
int wolfSSL_GetSessionAtIndex(int idx, WOLFSSL_SESSION* session);

/*!
    \ingroup IO

    \brief WOLFSSL_SESSION構造体からピア証明書チェーンを返します。

    \return pointer ピア証明書チェーンを含むWOLFSSL_X509_CHAIN構造体へのポインタ。

    \param session WOLFSSL_SESSION構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_SESSION* session;
    WOLFSSL_X509_CHAIN* chain;
    ...
    chain = wolfSSL_SESSION_get_peer_chain(session);
    if(!chain){
    	// チェーンがありませんでした。失敗ケース。
    }
    \endcode

    \sa wolfSSL_GetSessionAtIndex
    \sa wolfSSL_GetSessionIndex
    \sa AddSession
*/

    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);

/*!
    \ingroup Setup

    \brief この関数はリモートピアの検証方法を設定し、また検証コールバックをSSLコンテキストに登録できるようにします。検証コールバックは検証失敗が発生した場合にのみ呼び出されます。検証コールバックが不要な場合は、verify_callbackにNULLポインタを使用できます。ピア証明書の検証モードは論理OR演算されたフラグのリストです。可能なフラグ値は以下の通りです。SSL_VERIFY_NONE クライアントモード：クライアントはサーバーから受信した証明書を検証せず、ハンドシェイクは通常通り続行されます。サーバーモード：サーバーはクライアントに証明書要求を送信しません。したがって、クライアント検証は有効になりません。SSL_VERIFY_PEER クライアントモード：クライアントはハンドシェイク中にサーバーから受信した証明書を検証します。これはwolfSSLではデフォルトで有効になっているため、このオプションを使用しても効果はありません。サーバーモード：サーバーはクライアントに証明書要求を送信し、受信したクライアント証明書を検証します。SSL_VERIFY_FAIL_IF_NO_PEER_CERT クライアントモード：クライアント側で使用しても効果はありません。サーバーモード：クライアントが要求されたときに証明書の送信に失敗した場合（SSLサーバーでSSL_VERIFY_PEERを使用している場合）、サーバー側で検証が失敗します。SSL_VERIFY_FAIL_EXCEPT_PSK クライアントモード：クライアント側で使用しても効果はありません。サーバーモード：検証はSSL_VERIFY_FAIL_IF_NO_PEER_CERTと同じですが、PSK接続の場合を除きます。PSK接続が行われている場合、接続はピア証明書なしで続行されます。

    \return none 返り値はありません。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param mode ピアの証明書の検証モードを示すフラグ。
    \param verify_callback 検証が失敗したときに呼び出されるコールバック。コールバックが不要な場合は、verify_callbackにNULLポインタを使用できます。

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

    \brief この関数はリモートピアの検証方法を設定し、また検証コールバックをSSLセッションに登録できるようにします。検証コールバックは検証失敗が発生した場合にのみ呼び出されます。検証コールバックが不要な場合は、verify_callbackにNULLポインタを使用できます。ピア証明書の検証モードは論理OR演算されたフラグのリストです。可能なフラグ値は以下の通りです。SSL_VERIFY_NONE クライアントモード：クライアントはサーバーから受信した証明書を検証せず、ハンドシェイクは通常通り続行されます。サーバーモード：サーバーはクライアントに証明書要求を送信しません。したがって、クライアント検証は有効になりません。SSL_VERIFY_PEER クライアントモード：クライアントはハンドシェイク中にサーバーから受信した証明書を検証します。これはwolfSSLではデフォルトで有効になっているため、このオプションを使用しても効果はありません。サーバーモード：サーバーはクライアントに証明書要求を送信し、受信したクライアント証明書を検証します。SSL_VERIFY_FAIL_IF_NO_PEER_CERT クライアントモード：クライアント側で使用しても効果はありません。サーバーモード：クライアントが要求されたときに証明書の送信に失敗した場合（SSLサーバーでSSL_VERIFY_PEERを使用している場合）、サーバー側で検証が失敗します。SSL_VERIFY_FAIL_EXCEPT_PSK クライアントモード：クライアント側で使用しても効果はありません。サーバーモード：検証はSSL_VERIFY_FAIL_IF_NO_PEER_CERTと同じですが、PSK接続の場合を除きます。PSK接続が行われている場合、接続はピア証明書なしで続行されます。

    \return none 返り値はありません。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param mode ピアの証明書の検証モードを示すフラグ。
    \param verify_callback 検証が失敗したときに呼び出されるコールバック。コールバックが不要な場合は、verify_callbackにNULLポインタを使用できます。

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

    \brief この関数は検証コールバック用のユーザーCTXオブジェクト情報を格納します。

    \return none 返り値はありません。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param ctx WOLFSSL構造体のverifyCbCtxメンバの値に設定されるvoidポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    (void*)ctx;
    ...
    if(ssl != NULL){
        wolfSSL_SetCertCbCtx(ssl, ctx);
    } else {
	    // エラーケース、SSLが適切に初期化されていません。
    }
    \endcode

    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx);

/*!
    \ingroup CertsKeys

    \brief この関数は検証コールバック用のユーザーCTXオブジェクト情報を格納します。

    \return none 返り値はありません。

    \param ctx WOLFSSL_CTX構造体へのポインタ。
    \param userCtx WOLFSSL_CTX構造体のverifyCbCtxメンバの値を設定するために使用されるvoidポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    void* userCtx = NULL; // ユーザー定義のコンテキストを割り当て
    ...
    if(ctx != NULL){
        wolfSSL_SetCertCbCtx(ctx, userCtx);
    } else {
        // エラーケース、SSLが適切に初期化されていません。
    }
    \endcode

    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx);

/*!
    \ingroup IO

    \brief この関数はSSLオブジェクト内でバッファリングされ、wolfSSL_read()によって読み取り可能な利用可能なバイト数を返します。

    \return int この関数は保留中のバイト数を返します。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int pending = 0;
    WOLFSSL* ssl = 0;
    ...

    pending = wolfSSL_pending(ssl);
    printf("バッファリングされ読み取り可能な%dバイトがあります", pending);
    \endcode

    \sa wolfSSL_recv
    \sa wolfSSL_read
    \sa wolfSSL_peek
*/
int  wolfSSL_pending(WOLFSSL*);

/*!
    \ingroup Debug

    \brief この関数はOpenSSL互換性（SSL_load_error_string）のためのものであり、何も動作を行いません。

    \return none 返り値はありません。

    \param none パラメータはありません。

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

    \brief この関数はwolfSSL_CTX_new()内で内部的に呼び出されます。この関数はwolfSSL_Init()のラッパーであり、wolfSSLがOpenSSL互換性レイヤーでコンパイルされた場合のOpenSSL互換性（SSL_library_init）のために存在します。wolfSSL_Init()は、より一般的に使用されるwolfSSL初期化関数です。

    \return SSL_SUCCESS 呼び出しが成功した場合に返されます。
    \return SSL_FATAL_ERROR 失敗時に返されます。

    \param none パラメータはありません。

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_library_init();
    if (ret != SSL_SUCCESS) {
	    // wolfSSLの初期化に失敗しました
    }
    ...
    \endcode

    \sa wolfSSL_Init
    \sa wolfSSL_Cleanup
*/
int  wolfSSL_library_init(void);

/*!
    \brief この関数はWOLFSSLセッションレベルでDevice Idを設定します。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG sslがNULLの場合。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定します。

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
    \brief この関数はWOLFSSL_CTXコンテキストレベルでDevice Idを設定します。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG sslがNULLの場合。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定します。

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
    \brief この関数はDevice Idを取得します。

    \return devId 成功時。
    \return INVALID_DEVID sslとctxの両方がNULLの場合。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。

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

    \brief この関数はSSLセッションキャッシングを有効または無効にします。動作はmodeに使用される値に依存します。modeに使用できる値は以下の通りです。SSL_SESS_CACHE_OFF - セッションキャッシングを無効にします。セッションキャッシングはデフォルトで有効になっています。SSL_SESS_CACHE_NO_AUTO_CLEAR - セッションキャッシュの自動フラッシュを無効にします。自動フラッシュはデフォルトで有効になっています。

    \return SSL_SUCCESS 成功時に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param mode セッションキャッシュの動作を変更するために使用される修飾子。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (ret != SSL_SUCCESS) {
        // SSLセッションキャッシングをオフにすることができませんでした。
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
    \brief この関数は、セッションシークレットコールバック関数を設定します。SessionSecretCb型は次のシグネチャを持ちます:int (*SessionSecretCb)(WOLFSSL* ssl, void* secret, int* secretSz, void* ctx)。WOLFSSL構造体のsessionSecretCbメンバが、パラメータcbに設定されます。

    \return SSL_SUCCESS 関数の実行がエラーを返さなかった場合に返されます。
    \return SSL_FATAL_ERROR WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb 上記のシグネチャを持つ関数ポインタであるSessionSecretCb型。
    \param ctx 保存されるユーザコンテキストへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    // SessionSecretCbのシグネチャ
    int SessionSecretCB (WOLFSSL* ssl, void* secret, int* secretSz,
    void* ctx) = SessionSecretCb;
    …
    int wolfSSL_set_session_secret_cb(ssl, SessionSecretCB, (void*)ssl->ctx){
	    // 関数本体。
    }
    \endcode

    \sa SessionSecretCb
*/
int  wolfSSL_set_session_secret_cb(WOLFSSL* ssl, SessionSecretCb cb, void* ctx);

/*!
    \ingroup IO

    \brief この関数は、セッションキャッシュをファイルに永続化します。追加のメモリ使用量のため、memsaveは使用しません。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。セッションキャッシュがファイルに書き込まれました。
    \return SSL_BAD_FILE fnameを開くことができないか、またはそれ以外の理由で破損している場合に返されます。
    \return FWRITE_ERROR XFWRITEがファイルへの書き込みに失敗した場合に返されます。
    \return BAD_MUTEX_E mutexロックの失敗があった場合に返されます。

    \param fname 書き込み用ファイルを指す定数char型ポインタ。

    _Example_
    \code
    const char* fname;
    ...
    if(wolfSSL_save_session_cache(fname) != SSL_SUCCESS){
    	// ファイルへの書き込みに失敗しました。
    }
    \endcode

    \sa XFWRITE
    \sa wolfSSL_restore_session_cache
    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_save_session_cache(const char* fname);

/*!
    \ingroup IO

    \brief この関数は、永続的なセッションキャッシュをファイルから復元します。追加のメモリ使用量のため、memstoreは使用しません。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。
    \return SSL_BAD_FILE 関数に渡されたファイルが破損しており、XFOPENで開くことができなかった場合に返されます。
    \return FREAD_ERROR ファイルがXFREADからの読み取りエラーを持っていた場合に返されます。
    \return CACHE_MATCH_ERROR セッションキャッシュヘッダのマッチングに失敗した場合に返されます。
    \return BAD_MUTEX_E mutexロックの失敗があった場合に返されます。

    \param fname 読み取られる定数char型ポインタファイル入力。

    _Example_
    \code
    const char *fname;
    ...
    if(wolfSSL_restore_session_cache(fname) != SSL_SUCCESS){
        // 失敗ケースです。関数はSSL_SUCCESSを返しませんでした。
    }
    \endcode

    \sa XFREAD
    \sa XFOPEN
*/
int  wolfSSL_restore_session_cache(const char* fname);

/*!
    \ingroup IO

    \brief この関数は、セッションキャッシュをメモリに永続化します。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。セッションキャッシュがメモリに正常に永続化されました。
    \return BAD_MUTEX_E mutexロックエラーがあった場合に返されます。
    \return BUFFER_E バッファサイズが小さすぎた場合に返されます。

    \param mem メモリコピーXMEMCPY()の宛先を表すvoid型ポインタ。
    \param sz memのサイズを表すint型。

    _Example_
    \code
    void* mem;
    int sz; // メモリバッファの最大サイズ。
    …
    if(wolfSSL_memsave_session_cache(mem, sz) != SSL_SUCCESS){
    	// 失敗ケースです。セッションキャッシュをメモリに永続化できませんでした。
    }
    \endcode

    \sa XMEMCPY
    \sa wolfSSL_get_session_cache_memsize
*/
int  wolfSSL_memsave_session_cache(void* mem, int sz);

/*!
    \ingroup IO

    \brief この関数は、永続的なセッションキャッシュをメモリから復元します。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。
    \return BUFFER_E メモリバッファが小さすぎる場合に返されます。
    \return BAD_MUTEX_E セッションキャッシュのmutexロックに失敗した場合に返されます。
    \return CACHE_MATCH_ERROR セッションキャッシュヘッダのマッチングに失敗した場合に返されます。

    \param mem 復元のソースを含む定数void型ポインタ。
    \param sz メモリバッファのサイズを表す整数。

    _Example_
    \code
    const void* memoryFile;
    int szMf;
    ...
    if(wolfSSL_memrestore_session_cache(memoryFile, szMf) != SSL_SUCCESS){
    	// 失敗ケースです。SSL_SUCCESSが返されませんでした。
    }
    \endcode

    \sa wolfSSL_save_session_cache
*/
int  wolfSSL_memrestore_session_cache(const void* mem, int sz);

/*!
    \ingroup IO

    \brief この関数は、セッションキャッシュの保存バッファがどのくらい大きくあるべきかを返します。

    \return int この関数は、セッションキャッシュの保存バッファのサイズを表す整数を返します。

    \param none パラメータなし。

    _Example_
    \code
    int sz = // エラーチェックのための最小サイズ;
    ...
    if(sz < wolfSSL_get_session_cache_memsize()){
        // メモリバッファが小さすぎます。
    }
    \endcode

    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_get_session_cache_memsize(void);

/*!
    \ingroup CertsKeys

    \brief この関数は、証明書キャッシュをメモリからファイルに書き込みます。

    \return SSL_SUCCESS CM_SaveCertCacheが正常に終了した場合に返されます。
    \return BAD_FUNC_ARG いずれかの引数がNULLの場合に返されます。
    \return SSL_BAD_FILE 証明書キャッシュ保存ファイルを開くことができなかった場合に返されます。
    \return BAD_MUTEX_E ロックmutexが失敗した場合に返されます。
    \return MEMORY_E メモリの割り当てに失敗した場合に返されます。
    \return FWRITE_ERROR 証明書キャッシュファイルの書き込みに失敗しました。

    \param ctx 証明書情報を保持するWOLFSSL_CTX構造体へのポインタ。
    \param fname 書き込み用ファイルを指す定数char型ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    const char* fname;
    ...
    if(wolfSSL_CTX_save_cert_cache(ctx, fname)){
	    // ファイルが書き込まれました。
    }
    \endcode

    \sa CM_SaveCertCache
    \sa DoMemSaveCertCache
*/
int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys

    \brief この関数は、証明書キャッシュをファイルから永続化します。

    \return SSL_SUCCESS 関数CM_RestoreCertCacheが正常に実行された場合に返されます。
    \return SSL_BAD_FILE XFOPENがXBADFILEを返した場合に返されます。ファイルが破損しています。
    \return MEMORY_E 一時バッファに割り当てられたメモリが失敗した場合に返されます。
    \return BAD_FUNC_ARG fnameまたはctxがNULL値を持つ場合に返されます。

    \param ctx 証明書情報を保持するWOLFSSL_CTX構造体へのポインタ。
    \param fname 読み取り用ファイルを指す定数char型ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* fname = "ファイルへのパス";
    ...
    if(wolfSSL_CTX_restore_cert_cache(ctx, fname)){
    	// 実行が成功したかどうかを確認します。
    }
    \endcode

    \sa CM_RestoreCertCache
    \sa XFOPEN
*/
int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys

    \brief この関数は、証明書キャッシュをメモリに永続化します。

    \return SSL_SUCCESS 関数の実行が成功し、エラーが発生しなかった場合に返されます。
    \return BAD_MUTEX_E WOLFSSL_CERT_MANAGERメンバcaLockが0(ゼロ)でなかったmutexエラー。
    \return BAD_FUNC_ARG ctx、mem、またはusedがNULLの場合、またはszが0(ゼロ)以下の場合に返されます。
    \return BUFFER_E 出力バッファmemが小さすぎました。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param mem 宛先(出力バッファ)へのvoid型ポインタ。
    \param sz 出力バッファのサイズ。
    \param used 証明書キャッシュヘッダのサイズへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol );
    void* mem;
    int sz;
    int* used;
    ...
    if(wolfSSL_CTX_memsave_cert_cache(ctx, mem, sz, used) != SSL_SUCCESS){
	    // 関数がエラーを返しました。
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

    \brief この関数は、証明書キャッシュをメモリから復元します。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG ctxまたはmemパラメータがNULLの場合、またはszパラメータが0以下の場合に返されます。
    \return BUFFER_E 証明書キャッシュのメモリバッファが小さすぎる場合に返されます。
    \return CACHE_MATCH_ERROR 証明書キャッシュヘッダの不一致があった場合に返されます。
    \return BAD_MUTEX_E ロックmutexが失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param mem 証明書キャッシュに復元される値を持つvoid型ポインタ。
    \param sz memパラメータのサイズを表すint型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    void* mem;
    int sz = (*int) sizeof(mem);
    …
    if(wolfSSL_CTX_memrestore_cert_cache(ssl->ctx, mem, sz)){
    	// 成功ケース
    }
    \endcode

    \sa CM_MemRestoreCertCache
*/
int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz);

/*!
    \ingroup CertsKeys

    \brief 証明書キャッシュの保存バッファに必要なサイズを返します。

    \return int 成功時にメモリサイズを表す整数値が返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合に返されます。
    \return BAD_MUTEX_E mutexロックエラーがあった場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたwolfSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol);
    ...
    int certCacheSize = wolfSSL_CTX_get_cert_cache_memsize(ctx);

    if(certCacheSize != BAD_FUNC_ARG || certCacheSize != BAD_MUTEX_E){
	// メモリサイズの取得に成功しました。
    }
    \endcode

    \sa CM_GetCertCacheMemSize
*/
int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief この関数は、指定されたWOLFSSL_CTXに対する暗号スイートリストを設定します。この暗号スイートリストは、このコンテキストを使用して作成された新しいSSLセッション(WOLFSSL)のデフォルトリストになります。リスト内の暗号は、優先度の高い順から低い順に並べる必要があります。wolfSSL_CTX_set_cipher_list()を呼び出すたびに、関数が呼び出されるたびに、特定のSSLコンテキストの暗号スイートリストが提供されたリストにリセットされます。暗号スイートリストであるlistは、nullで終端されたテキスト文字列であり、コロン区切りのリストです。例えば、listの1つの値は「DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256」となる可能性があります。有効な暗号値は、src/internal.cのcipher_names[]配列からの完全な名前値です(有効な暗号値の明確なリストについては、src/internal.cを確認してください)。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。
    \return SSL_FAILURE 失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param list 指定されたSSLコンテキストで使用する暗号スイートのnullで終端されたテキスト文字列およびコロン区切りリスト。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_cipher_list(ctx,
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256");
    if (ret != SSL_SUCCESS) {
    	// 暗号スイートリストの設定に失敗しました。
    }
    \endcode

    \sa wolfSSL_set_cipher_list
    \sa wolfSSL_CTX_new
*/
int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);

/*!
    \ingroup Setup

    \brief この関数は、指定されたWOLFSSLオブジェクト(SSLセッション)に対する暗号スイートリストを設定します。リスト内の暗号は、優先度の高い順から低い順に並べる必要があります。wolfSSL_set_cipher_list()を呼び出すたびに、関数が呼び出されるたびに、特定のSSLセッションの暗号スイートリストが提供されたリストにリセットされます。暗号スイートリストであるlistは、nullで終端されたテキスト文字列であり、コロン区切りのリストです。例えば、listの1つの値は「DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256」となる可能性があります。有効な暗号値は、src/internal.cのcipher_names[]配列からの完全な名前値です(有効な暗号値の明確なリストについては、src/internal.cを確認してください)。
    \return SSL_SUCCESS 関数が正常に完了すると返されます。
    \return SSL_FAILURE 失敗時に返されます。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param list null終端テキスト文字列であり、指定されたSSLセッションで使用する暗号スイートのコロン区切りリスト。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_cipher_list(ssl,
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256");
    if (ret != SSL_SUCCESS) {
    	// 暗号スイートリストの設定に失敗
    }
    \endcode

    \sa wolfSSL_CTX_set_cipher_list
    \sa wolfSSL_new
*/
int  wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list);

/*!
    \brief この関数は、WOLFSSL DTLSオブジェクトに対して、下層のUDP I/Oがノンブロッキングであることを通知します。アプリケーションがWOLFSSLオブジェクトを作成した後、それをノンブロッキングUDPソケットと共に使用する場合は、wolfSSL_dtls_set_using_nonblock()を呼び出してください。これにより、WOLFSSLオブジェクトは、EWOULDBLOCKを受け取ることがタイムアウトではなく、recvfrom呼び出しがブロックすることを意味すると認識できます。

    \return none 戻り値はありません。

    \param ssl wolfSSL_new()で作成されたDTLSセッションへのポインタ。
    \param nonblock WOLFSSLオブジェクトのノンブロッキングフラグを設定するための値。ノンブロッキングを指定する場合は1を、そうでない場合は0を使用してください。

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
    \brief この関数により、アプリケーションはwolfSSLがUDPでノンブロッキングI/Oを使用しているかどうかを判定できます。wolfSSLがノンブロッキングI/Oを使用している場合、この関数は1を返し、それ以外の場合は0を返します。アプリケーションがWOLFSSLオブジェクトを作成した後、それをノンブロッキングUDPソケットと共に使用する場合は、wolfSSL_dtls_set_using_nonblock()を呼び出してください。これにより、WOLFSSLオブジェクトは、EWOULDBLOCKを受け取ることがタイムアウトではなく、recvfrom呼び出しがブロックすることを意味すると認識できます。この関数はDTLSセッションにのみ意味があります。

    \return 0 下層のI/Oがブロッキングです。
    \return 1 下層のI/Oがノンブロッキングです。

    \param ssl wolfSSL_new()で作成されたDTLSセッションへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_dtls_get_using_nonblock(ssl);
    if (ret == 1) {
    	// 下層のI/Oはノンブロッキング
    }
    ...
    \endcode

    \sa wolfSSL_dtls_set_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_using_nonblock
*/
int  wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl);
/*!
    \brief この関数は、WOLFSSLオブジェクトの現在のタイムアウト値を秒単位で返します。ノンブロッキングソケットを使用する場合、ユーザコード内の何かが、利用可能な受信データをいつチェックするか、およびどのくらい待機しているかを決定する必要があります。この関数が返す値は、アプリケーションがどのくらい待機すべきかを示します。

    \return seconds 現在のDTLSタイムアウト値(秒単位)。
    \return NOT_COMPILED_IN wolfSSLがDTLSサポート付きでビルドされていない場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int timeout = 0;
    WOLFSSL* ssl;
    ...
    timeout = wolfSSL_get_dtls_current_timeout(ssl);
    printf("DTLS timeout (sec) = %d\n", timeout);
    \endcode

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);
/*!
    \brief この関数は、アプリケーションがより短いタイムアウトを設定すべき場合にtrueを返します。ノンブロッキングソケットを使用する場合、ユーザコード内の何かが、利用可能なデータをいつチェックするか、およびどのくらい待機する必要があるかを決定する必要があります。この関数がtrueを返す場合、ライブラリはすでに通信の中断を検出していますが、他のピアからのメッセージがまだ転送中である可能性に備えて、もう少し待機したいことを意味します。このタイマーの値を微調整するのはアプリケーション次第であり、適切な値はdtls_get_current_timeout() / 4かもしれません。

    \return true アプリケーションコードがより短いタイムアウトを設定すべき場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_set_send_more_acks
*/
int  wolfSSL_dtls13_use_quick_timeout(WOLFSSL *ssl);
/*!
  \ingroup Setup

    \brief この関数は、中断を検出したときにライブラリがACKを他のピアに即座に送信すべきかどうかを設定します。ACKを即座に送信すると最小のレイテンシが保証されますが、必要以上に帯域幅を消費する可能性があります。アプリケーションが自分でタイマーを管理し、このオプションが0に設定されている場合、アプリケーションコードはwolfSSL_dtls13_use_quick_timeout()を使用して、これらの遅延ACKを送信するためにより短いタイムアウトを設定すべきかどうかを判定できます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param value オプションを設定する場合は1、オプションを無効にする場合は0。

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_use_quick_timeout
*/
void  wolfSSL_dtls13_set_send_more_acks(WOLFSSL *ssl, int value);

/*!
    \ingroup Setup

    \brief この関数はdtlsタイムアウトを設定します。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。SSLのdtls_timeout_initおよびdtls_timeoutメンバが設定されています。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLであるか、またはタイムアウトが0より大きくない場合に返されます。また、timeout引数が許容される最大値を超える場合にも返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param timeout WOLFSSL構造体のdtls_timeout_initメンバに設定されるint型の値。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUT;
    ...
    if(wolfSSL_dtls_set_timeout_init(ssl, timeout)){
    	// dtlsタイムアウトが設定された
    } else {
    	// DTLSタイムアウトの設定に失敗
    }
    \endcode

    \sa wolfSSL_dtls_set_timeout_max
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int);

/*!
    \brief この関数は最大dtlsタイムアウトを設定します。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLであるか、timeout引数が0より大きくないか、またはWOLFSSL構造体のdtls_timeout_initメンバより小さい場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param timeout dtls最大タイムアウトを表すint型の値。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUTVAL;
    ...
    int ret = wolfSSL_dtls_set_timeout_max(ssl);
    if(!ret){
    	// 最大タイムアウトの設定に失敗
    }
    \endcode

    \sa wolfSSL_dtls_set_timeout_init
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int);

/*!
    \brief DTLSでノンブロッキングソケットを使用する場合、制御コードが送信がタイムアウトしたと判断したときに、この関数をWOLFSSLオブジェクトに対して呼び出す必要があります。この関数は、タイムアウト値の調整を含め、最後の送信を再試行するために必要なアクションを実行します。時間が経過しすぎた場合、失敗が返されます。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FATAL_ERROR ピアからの応答なしで再送信またはタイムアウトが多すぎた場合に返されます。
    \return NOT_COMPILED_IN wolfSSLがDTLSサポート付きでコンパイルされていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    使用例については以下のファイルを参照してください:
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
    \brief DTLSでノンブロッキングソケットを使用する場合、この関数は予想されるタイムアウト値と再送信カウントを無視して、最後のハンドシェイクフライトを再送信します。これは、DTLSを使用していて、タイムアウトと再試行回数さえも管理する必要があるアプリケーションに役立ちます。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FATAL_ERROR ピアからの応答なしで再送信またはタイムアウトが多すぎた場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

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
    \brief この関数は、SSLセッションがDTLSを使用するように設定されているかどうかを判定するために使用されます。

    \return 1 SSLセッション(ssl)がDTLSを使用するように設定されている場合、この関数は1を返します。
    \return 0 それ以外の場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls(ssl);
    if (ret) {
    	// SSLセッションはDTLSを使用するように設定されている
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls(WOLFSSL* ssl);

/*!
    \brief この関数は、DTLSピアpeer(sockaddr_in)をサイズpeerSzで設定します。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FAILURE 失敗時に返されます。
    \return SSL_NOT_IMPLEMENTED wolfSSLがDTLSサポート付きでコンパイルされていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param peer ピアのsockaddr_in構造体へのポインタ。NULLの場合、ssl内のピア情報がクリアされます。
    \param peerSz peerが指すsockaddr_in構造体のサイズ。0の場合、ssl内のピア情報がクリアされます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // DTLSピアの設定に失敗
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_set_pending_peer
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz);

/*!
    \brief この関数は、保留中のDTLSピアpeer(sockaddr_in)をサイズpeerSzで設定します。これにより、次のレコードの保護を正常に解除したときに通常のピアにアップグレードされる保留中のピアが設定されます。これは、ピアのアドレスが変更される可能性があるシナリオで、オフパス攻撃者がピアアドレスを変更するのを防ぐのに役立ちます。これは、新しいピアアドレスへのシームレスで安全な移行を可能にするために、Connection IDと共に使用する必要があります。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FAILURE 失敗時に返されます。
    \return SSL_NOT_IMPLEMENTED wolfSSLがDTLSサポート付きでコンパイルされていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param peer ピアのsockaddr_in構造体へのポインタ。NULLの場合、ssl内のピア情報がクリアされます。
    \param peerSz peerが指すsockaddr_in構造体のサイズ。0の場合、ssl内のピア情報がクリアされます。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_pending_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // DTLSピアの設定に失敗
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer,
                                   unsigned int peerSz);

/*!
    \brief この関数は、現在のDTLSピアのsockaddr_in(サイズpeerSz)を取得します。この関数はpeerSzを、SSLセッションに格納されている実際のDTLSピアサイズと比較します。ピアがpeerに収まる場合、ピアのsockaddr_inがpeerにコピーされ、peerSzがpeerのサイズに設定されます。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FAILURE 失敗時に返されます。
    \return SSL_NOT_IMPLEMENTED wolfSSLがDTLSサポート付きでコンパイルされていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param peer ピアのsockaddr_in構造体を格納するメモリ位置へのポインタ。
    \param peerSz 入出力サイズ。入力として、peerが指す割り当てられたメモリのサイズ。出力として、peerが指す実際のsockaddr_in構造体のサイズ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...    ret = wolfSSL_dtls_get_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // DTLSピアの取得に失敗しました
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz);

/*!
    \brief この関数は現在のDTLSピアのsockaddr_in（サイズpeerSz）を取得します。これはwolfSSL_dtls_get_peer()のゼロコピー代替です。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FAILURE 失敗時に返されます。
    \return SSL_NOT_IMPLEMENTED wolfSSLがDTLSサポートでコンパイルされていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param peer ピアアドレスを保持する内部バッファを返すためのポインタ。
    \param peerSz peerが指す実際のsockaddr_in構造体のサイズを出力します。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in* addr;
    unsigned int addrSz;
    ...
    ret = wolfSSL_dtls_get_peer(ssl, &addr, &addrSz);
    if (ret != SSL_SUCCESS) {
	    // DTLSピアの取得に失敗しました
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_get0_peer(WOLFSSL* ssl, const void** peer,
                            unsigned int* peerSz);

/*!
    \ingroup Debug

    \brief この関数はwolfSSL_get_error()によって返されたエラーコードを、より人間が読みやすいエラー文字列に変換します。errNumberはwolfSSL_get_error()によって返されたエラーコードであり、dataはエラー文字列が配置される格納バッファです。dataの最大長はデフォルトで80文字であり、wolfssl/wolfcrypt/error.hのMAX_ERROR_SZで定義されています。

    \return success 正常に完了した場合、この関数はdataで返されるのと同じ文字列を返します。
    \return failure 失敗時には、この関数は適切な失敗理由msgを含む文字列を返します。

    \param errNumber wolfSSL_get_error()によって返されたエラーコード。
    \param data errNumberに一致する人間が読みやすいエラー文字列を含む出力バッファ。

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf("err = %d, %s\n", err, buffer);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data);

/*!
    \ingroup Debug

    \brief この関数はwolfSSL_ERR_error_string()のバージョンであり、lenはbufに書き込まれる最大文字数を指定します。wolfSSL_ERR_error_string()と同様に、この関数はwolfSSL_get_error()から返されたエラーコードをより人間が読みやすいエラー文字列に変換します。人間が読みやすい文字列はbufに配置されます。

    \return none 返り値はありません。

    \param e wolfSSL_get_error()によって返されたエラーコード。
    \param buff eに一致する人間が読みやすいエラー文字列を含む出力バッファ。
    \param len bufに書き込まれる最大文字数。

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string_n(err, buffer, 80);
    printf("err = %d, %s\n", err, buffer);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long len);

/*!
    \ingroup TLS

    \brief この関数はOptions構造体のcloseNotify、connReset、またはsentNotifyメンバのシャットダウン条件をチェックします。Options構造体はWOLFSSL構造体内にあります。

    \return 1 SSL_SENT_SHUTDOWNが返されます。
    \return 2 SSL_RECEIVED_SHUTDOWNが返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体への定数ポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    int ret;
    ret = wolfSSL_get_shutdown(ssl);

    if(ret == 1){
	    // SSL_SENT_SHUTDOWN
    } else if(ret == 2){
	    // SSL_RECEIVED_SHUTDOWN
    } else {
	    // 致命的エラー。
    }
    \endcode

    \sa wolfSSL_SESSION_free
*/
int  wolfSSL_get_shutdown(const WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数はoptions構造体のresumingメンバを返します。このフラグはセッションを再利用するかどうかを示します。再利用しない場合、新しいセッションを確立する必要があります。

    \return この関数はセッション再利用のフラグを表すOptions構造体に保持されたint型を返します。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(!wolfSSL_session_reused(sslResume)){
	    // セッション再利用は許可されていません。
    }
    \endcode

    \sa wolfSSL_SESSION_free
    \sa wolfSSL_GetSessionIndex
    \sa wolfSSL_memsave_session_cache
*/
int  wolfSSL_session_reused(WOLFSSL* ssl);

/*!
    \ingroup TLS

    \brief この関数は接続が確立されているかどうかをチェックします。

    \return 0 接続が確立されていない場合に返されます、つまりWOLFSSL構造体がNULLまたはハンドシェイクが完了していない場合。
    \return 1 接続が確立されている場合に返されます、つまりWOLFSSLハンドシェイクが完了している場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _EXAMPLE_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_is_init_finished(ssl)){
	    // ハンドシェイクが完了し、接続が確立されています
    }
    \endcode

    \sa wolfSSL_set_accept_state
    \sa wolfSSL_get_keys
    \sa wolfSSL_set_shutdown
*/
int  wolfSSL_is_init_finished(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief 使用されているSSLバージョンを文字列として返します。

    \return "SSLv3" SSLv3を使用しています
    \return "TLSv1" TLSv1を使用しています
    \return "TLSv1.1" TLSv1.1を使用しています
    \return "TLSv1.2" TLSv1.2を使用しています
    \return "TLSv1.3" TLSv1.3を使用しています
    \return "DTLS" DTLSを使用しています
    \return "DTLSv1.2" DTLSv1.2を使用しています
    \return "unknown" 使用されているTLSのバージョンを判定する際に問題が発生しました。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // 何らかのwolfSSLメソッド
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);
    printf(wolfSSL_get_version("Using version: %s", ssl));
    \endcode

    \sa wolfSSL_lib_version
*/
const char*  wolfSSL_get_version(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief sslセッションが使用している現在の暗号スイートを返します。

    \return ssl->options.cipherSuite 現在の暗号スイートを表す整数。
    \return 0 提供されたsslセッションがnullです。

    \param ssl チェックするSSLセッション。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // 何らかのwolfSSLメソッド
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_get_current_cipher_suite(ssl) == 0)
    {
        // 暗号スイートの取得エラー
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_list
*/
int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数はsslセッション内の現在の暗号へのポインタを返します。

    \return この関数はWOLFSSL構造体のcipherメンバのアドレスを返します。これはWOLFSSL_CIPHER構造体へのポインタです。
    \return NULL WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    WOLFSSL_CIPHER* cipherCurr = wolfSSL_get_current_cipher;

    if(!cipherCurr){
    	// 失敗ケース。
    } else {
    	// 暗号がcipherCurrに返されました
    }
    \endcode

    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数はSSLオブジェクト内の暗号スイートを利用可能なスイートと照合し、文字列表現を返します。

    \return string この関数は一致した暗号スイートの文字列表現を返します。
    \return none 一致するスイートがない場合は"None"を返します。

    \param cipher WOLFSSL_CIPHER構造体への定数ポインタ。

    _Example_
    \code
    // DHE_RSA ...の形式で暗号名を取得します
    const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl){
	WOLFSSL_CIPHER* cipher;
	const char* fullName;
    …
	cipher = wolfSSL_get_curent_cipher(ssl);
	fullName = wolfSSL_CIPHER_get_name(cipher);

	if(fullName){
		// 返された暗号の健全性チェック
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

    \brief この関数はSSLオブジェクト内の暗号スイートを利用可能なスイートと照合します。

    \return この関数は一致したスイートの文字列値を返します。一致するスイートがない場合は"None"を返します。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    #ifdef WOLFSSL_DTLS
    …
    // 有効なスイートが使用されていることを確認
    if(wolfSSL_get_cipher(ssl) == NULL){
	    WOLFSSL_MSG("インポートされた暗号スイートと一致しません");
	    return MATCH_SUITE_ERROR;
    }
    …
    #endif // WOLFSSL_DTLS
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
const char*  wolfSSL_get_cipher(WOLFSSL*);

/*!
    \ingroup Setup

    \brief この関数はWOLFSSL構造体からWOLFSSL_SESSIONを参照型として返します。これにはwolfSSL_SESSION_freeを呼び出してセッション参照を解放する必要があります。指されるWOLFSSL_SESSIONには、セッション再開を実行し、新しいハンドシェイクなしで接続を再確立するために必要なすべての情報が含まれています。セッション再開のために、セッションオブジェクトでwolfSSL_shutdown()を呼び出す前に、アプリケーションはwolfSSL_get1_session()の呼び出しでオブジェクトからセッションIDを保存する必要があります、これはセッションへのポインタを返します。後で、アプリケーションは新しいWOLFSSLオブジェクトを作成し、wolfSSL_set_session()で保存されたセッションを割り当てる必要があります。この時点で、アプリケーションはwolfSSL_connect()を呼び出すことができ、wolfSSLはセッションの再開を試みます。wolfSSLサーバーコードはデフォルトでセッション再開を許可します。wolfSSL_get1_session()によって返されたオブジェクトは、アプリケーションが使用を終えた後、wolfSSL_SESSION_free()を呼び出すことによって解放する必要があります。

    \return WOLFSSL_SESSION 成功時にセッションポインタを返します。
    \return NULL sslがNULL、SSLセッションキャッシュが無効、wolfSSLがセッションIDを利用できない、またはmutex関数が失敗した場合に返されます。

    \param ssl セッションを取得するWOLFSSL構造体。

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* ses;    // ハンドシェイクを試行/完了
    wolfSSL_connect(ssl);
    ses  = wolfSSL_get1_session(ssl);
    // ses情報を確認
    // 切断/新しいSSLインスタンスをセットアップ
    wolfSSL_set_session(ssl, ses);
    // ハンドシェイクを試行/再開
    wolfSSL_SESSION_free(ses);
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_SESSION_free
*/
WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief wolfSSLv23_client_method()関数は、アプリケーションがクライアントであり、SSL 3.0からTLS 1.3までの間でサーバがサポートする最も高いプロトコルバージョンをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいWOLFSSL_METHOD構造体のためのメモリを割り当て、初期化します。wolfSSLのクライアントとサーバの両方は、堅牢なバージョンダウングレード機能を持っています。どちらか一方で特定のプロトコルバージョンメソッドが使用された場合、そのバージョンのみがネゴシエートされるか、エラーが返されます。例えば、TLSv1を使用するクライアントがSSLv3のみのサーバに接続しようとすると失敗し、同様にTLSv1.1への接続も失敗します。この問題を解決するために、wolfSSLv23_client_method()関数を使用するクライアントは、サーバがサポートする最も高いプロトコルバージョンを使用し、必要に応じてSSLv3までダウングレードします。この場合、クライアントはSSLv3からTLSv1.3までを実行しているサーバに接続できます。

    \return pointer 成功時、WOLFSSL_METHODへのポインタ。
    \return Failure XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータなし。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;
    method = wolfSSLv23_client_method();
    if (method == NULL) {
	    // メソッドを取得できませんでした
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

    \brief これは、内部メモリバッファの先頭にバイトポインタを設定するために使用されます。

    \return size 成功時、バッファのサイズが返されます。
    \return SSL_FATAL_ERROR エラーケースが発生した場合。

    \param bio メモリバッファを取得するWOLFSSL_BIO構造体。
    \param p メモリバッファに設定するバイトポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    const byte* p;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_get_mem_data(bio, &p);
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,void* p);

/*!
    \ingroup IO

    \brief bioが使用するファイルディスクリプタを設定します。

    \return SSL_SUCCESS(1) 成功時。

    \param bio fdを設定するWOLFSSL_BIO構造体。
    \param fd 使用するファイルディスクリプタ。
    \param closeF fdをクローズする際の動作フラグ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int fd;
    // bioをセットアップ
    wolfSSL_BIO_set_fd(bio, fd, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int flag);

/*!
    \ingroup IO

    \brief クローズフラグを設定します。これは、BIOが解放される際にI/Oストリームをクローズすべきかを示すために使用されます。

    \return SSL_SUCCESS(1) 成功時。

    \param bio WOLFSSL_BIO構造体。
    \param flag I/Oストリームをクローズする際の動作フラグ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // bioをセットアップ
    wolfSSL_BIO_set_close(bio, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_set_close(WOLFSSL_BIO *b, long flag);

/*!
    \ingroup IO

    \brief これは、BIO_SOCKETタイプのWOLFSSL_BIO_METHODを取得するために使用されます。

    \return WOLFSSL_BIO_METHOD ソケットタイプであるWOLFSSL_BIO_METHOD構造体へのポインタ。

    \param none パラメータなし。

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

    \brief これは、WOLFSSL_BIOの書き込みバッファのサイズを設定するために使用されます。書き込みバッファが以前に設定されていた場合、この関数はサイズをリセットする際にそれを解放します。これは、読み取りと書き込みのインデックスを0にリセットする点でwolfSSL_BIO_resetに似ています。

    \return SSL_SUCCESS 書き込みバッファの設定に成功した場合。
    \return SSL_FAILURE エラーケースが発生した場合。

    \param bio fdを設定するWOLFSSL_BIO構造体。
    \param size 割り当てるバッファのサイズ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret = wolfSSL_BIO_set_write_buf_size(bio, 15000);
    // 戻り値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size);

/*!
    \ingroup IO

    \brief これは、2つのbioをペアにするために使用されます。ペアになったbioは双方向パイプのように動作し、一方への書き込みはもう一方から読み取ることができ、その逆も同様です。両方のbioが同じスレッドにあることが期待されます。この関数はスレッドセーフではありません。2つのbioのうちの1つを解放すると、両方のペアが解除されます。いずれかのbioに書き込みバッファサイズが以前に設定されていなかった場合、ペアになる前にデフォルトサイズの17000(WOLFSSL_BIO_SIZE)に設定されます。

    \return SSL_SUCCESS 2つのbioのペア化に成功した場合。
    \return SSL_FAILURE エラーケースが発生した場合。

    \param b1 ペアを設定するWOLFSSL_BIO構造体。
    \param b2 ペアを完成させる2番目のWOLFSSL_BIO構造体。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BIO* bio2;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    ret = wolfSSL_BIO_make_bio_pair(bio, bio2);
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2);

/*!
    \ingroup IO

    \brief これは、読み取り要求フラグを0に戻すために使用されます。

    \return SSL_SUCCESS 値の設定に成功した場合。
    \return SSL_FAILURE エラーケースが発生した場合。

    \param bio 読み取り要求フラグを設定するWOLFSSL_BIO構造体。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    ...
    ret = wolfSSL_BIO_ctrl_reset_read_request(bio);
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new, wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_new, wolfSSL_BIO_free
*/
int  wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief これは、読み取り用のバッファポインタを取得するために使用されます。wolfSSL_BIO_nreadとは異なり、内部読み取りインデックスは関数呼び出しから返される数だけ進められません。返される値を超えて読み取ると、配列の境界外を読み取る結果になる可能性があります。

    \return ＞=0 成功時、読み取るバイト数を返します。

    \param bio 読み取るWOLFSSL_BIO構造体。
    \param buf 読み取り配列の先頭に設定するポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // bioをセットアップ
    ret = wolfSSL_BIO_nread0(bio, &bufPt); // 可能な限り多くのバイトを読み取り
    // 負のret値を確認
    // bufPtからretバイトを読み取り
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite0
*/
int  wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf);

/*!
    \ingroup IO

    \brief これは、読み取り用のバッファポインタを取得するために使用されます。内部読み取りインデックスは、関数呼び出しから返される数だけ進められ、bufは読み取るバッファの先頭を指します。読み取りバッファ内のバイト数がnumで要求された値より少ない場合、より小さい値が返されます。返される値を超えて読み取ると、配列の境界外を読み取る結果になる可能性があります。

    \return ＞=0 成功時、読み取るバイト数を返します。
    \return WOLFSSL_BIO_ERROR(-1) 読み取るものがない場合のエラーケースで-1を返します。

    \param bio 読み取るWOLFSSL_BIO構造体。
    \param buf 読み取り配列の先頭に設定するポインタ。
    \param num 読み取りを試みるバイト数。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;

    // bioをセットアップ
    ret = wolfSSL_BIO_nread(bio, &bufPt, 10); // 10バイトの読み取りを試行
    // 負のret値を確認
    // bufPtからretバイトを読み取り
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite
*/
int  wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO

    \brief 関数が返す数だけのバイトを書き込むためのバッファへのポインタを取得します。返される値よりも多くのバイトを返されたポインタに書き込むと、境界外への書き込みになる可能性があります。

    \return int バッファポインタに書き込むことができるバイト数を返します。
    \return WOLFSSL_BIO_UNSET(-2) bioペアの一部ではない場合。
    \return WOLFSSL_BIO_ERROR(-1) 書き込むスペースがこれ以上ない場合。

    \param bio 書き込むWOLFSSL_BIO構造体。
    \param buf 書き込むバッファへのポインタ。
    \param num 書き込みたいバイト数。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // bioをセットアップ
    ret = wolfSSL_BIO_nwrite(bio, &bufPt, 10); // 10バイトの書き込みを試行
    // 負のret値を確認
    // bufPtにretバイトを書き込み
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_nread
*/
int  wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO

    \brief bioを初期状態にリセットします。例えば、BIO_BIOタイプの場合、これは読み取りと書き込みのインデックスをリセットします。

    \return 0 bioのリセットに成功した場合。
    \return WOLFSSL_BIO_ERROR(-1) 不正な入力またはリセットに失敗した場合に返されます。

    \param bio リセットするWOLFSSL_BIO構造体。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // bioをセットアップ
    wolfSSL_BIO_reset(bio);
    //ptを使用
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_reset(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief この関数は、ファイルポインタを指定されたオフセットに調整します。これはファイルの先頭からのオフセットです。

    \return 0 シークに成功した場合。
    \return -1 エラーケースが発生した場合。

    \param bio 設定するWOLFSSL_BIO構造体。
    \param ofs ファイルへのオフセット。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, &fp);
    // ret値を確認
    ret  = wolfSSL_BIO_seek(bio, 3);
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs);/*!
    \ingroup IO

    \brief ファイルを設定し、書き込むために使用されます。ファイル内の既存データを上書きし、bioが解放される際にファイルを閉じるよう設定されます。

    \return SSL_SUCCESS ファイルのオープンと設定が成功した場合。
    \return SSL_FAILURE エラーが発生した場合。

    \param bio ファイルを設定するWOLFSSL_BIO構造体。
    \param name 書き込み先のファイル名。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_write_filename(bio, "test.txt");
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_file
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name);

/*!
    \ingroup IO

    \brief ファイル終端値を設定するために使用されます。一般的な値は-1で、期待される正の値と混同しないようにします。

    \return 0 完了時に返されます。

    \param bio ファイル終端値を設定するWOLFSSL_BIO構造体。
    \param v bioに設定する値。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_set_mem_eof_return(bio, -1);
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v);

/*!
    \ingroup IO

    \brief WOLFSSL_BIOメモリポインタのgetter関数です。

    \return SSL_SUCCESS ポインタの取得に成功した場合、SSL_SUCCESSが返されます(現在の値は1)。
    \return SSL_FAILURE NULL引数が渡された場合に返されます(現在の値は0)。

    \param bio メモリポインタを取得するためのWOLFSSL_BIO構造体へのポインタ。
    \param ptr 現在char*である構造体。bioのメモリを指すように設定されます。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BUF_MEM* pt;
    // bioをセットアップ
    wolfSSL_BIO_get_mem_ptr(bio, &pt);
    // ptを使用
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **m);

/*!
    \ingroup CertsKeys

    \brief この関数はx509の名前をバッファにコピーします。

    \return 関数が正常に実行された場合、WOLFSSL_X509_NAME構造体のnameメンバーのデータを持つバッファへのcharポインタが返されます。

    \param name WOLFSSL_X509構造体へのポインタ。
    \param in WOLFSSL_X509_NAME構造体からコピーされた名前を保持するバッファ。
    \param sz バッファの最大サイズ。

    _Example_
    \code
    WOLFSSL_X509 x509;
    char* name;
    ...
    name = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(name <= 0){
    	// バッファに何もありません
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

    \brief この関数は証明書の発行者名を返します。

    \return point 渡されたcertがNULLでない場合、WOLFSSL_X509構造体のissuerメンバーへのポインタが返されます。
    \return NULL 渡されたcertがNULLの場合。

    \param cert WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509;
    WOLFSSL_X509_NAME issuer;
    ...
    issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(!issuer){
    	// NULLが返されました
    } else {
    	// issuerは証明書の発行者名を保持しています
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

    \brief この関数はWOLFSSL_X509構造体のsubjectメンバーを返します。

    \return pointer WOLFSSL_X509_NAME構造体へのポインタ。WOLFSSL_X509構造体がNULLの場合、または構造体のsubjectメンバーがNULLの場合、ポインタはNULLになる可能性があります。

    \param cert WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* cert;
    WOLFSSL_X509_NAME name;
    …
    name = wolfSSL_X509_get_subject_name(cert);
    if(name == NULL){
	    // NULLケースを処理
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_X509_NAME*  wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief WOLFSSL_X509構造体のisCaメンバーをチェックし、その値を返します。

    \return isCA WOLFSSL_X509構造体のisCaメンバーの値が返されます。
    \return 0 有効なx509構造体が渡されなかった場合に返されます。

    \param cert WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_X509_get_isCA(ssl)){
    	// これはCAです
    }else {
    	// 失敗ケース
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
*/
int  wolfSSL_X509_get_isCA(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief この関数は渡されたNID値に関連するテキストを取得します。

    \return int テキストバッファのサイズを返します。

    \param name テキストを検索するWOLFSSL_X509_NAME。
    \param nid 検索するNID。
    \param buf 見つかったテキストを保持するバッファ。
    \param len バッファの長さ。

    _Example_
    \code
    WOLFSSL_X509_NAME* name;
    char buffer[100];
    int bufferSz;
    int ret;
    // WOLFSSL_X509_NAMEを取得
    ret = wolfSSL_X509_NAME_get_text_by_NID(name, NID_commonName,
    buffer, bufferSz);

    // ret値を確認
    \endcode

    \sa none
*/
int wolfSSL_X509_NAME_get_text_by_NID(WOLFSSL_X509_NAME* name, int nid,
                                      char* buf, int len);

/*!
    \ingroup CertsKeys

    \brief この関数はWOLFSSL_X509構造体のsigOIDメンバーに格納されている値を返します。

    \return 0 WOLFSSL_X509構造体がNULLの場合に返されます。
    \return int x509オブジェクトから取得された整数値が返されます。

    \param cert WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509SigType = wolfSSL_X509_get_signature_type(x509);

    if(x509SigType != EXPECTED){
	    // 予期しない値を処理
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

    \param x509 WOLFSSL_X509構造体へのポインタ。

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

    \brief X509署名を取得し、バッファに格納します。

    \return SSL_SUCCESS 関数が正常に実行された場合に返されます。署名はバッファに読み込まれます。
    \return SSL_FATAL_ERRROR x509構造体またはbufSzメンバーがNULLの場合に返されます。sig構造体のlengthメンバー(sigはx509のメンバー)のチェックもあります。

    \param x509 WOLFSSL_X509構造体へのポインタ。
    \param buf バッファへのcharポインタ。
    \param bufSz バッファのサイズへの整数ポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    unsigned char* buf; // 初期化
    int* bufSz = sizeof(buf)/sizeof(unsigned char);
    ...
    if(wolfSSL_X509_get_signature(x509, buf, bufSz) != SSL_SUCCESS){
	    // 関数は正常に実行されませんでした
    } else{
	    // バッファは正しく書き込まれました
    }
    \endcode

    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_get_signature_type
    \sa wolfSSL_X509_get_device_type
*/
int wolfSSL_X509_get_signature(WOLFSSL_X509* x509, unsigned char* buf, int* bufSz);

/*!
    \ingroup CertsKeys

    \brief この関数はWOLFSSL_X509_STORE構造体に証明書を追加します。

    \return SSL_SUCCESS 証明書が正常に追加された場合。
    \return SSL_FATAL_ERROR 証明書が正常に追加されなかった場合。

    \param str 証明書を追加する証明書ストア。
    \param x509 追加する証明書。

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    WOLFSSL_X509* x509;
    int ret;
    ret = wolfSSL_X509_STORE_add_cert(str, x509);
    // ret値を確認
    \endcode

    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_STORE_add_cert(WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief この関数はWOLFSSL_X509_STORE_CTX構造体のchain変数のgetter関数です。現在、chainは入力されていません。

    \return pointer 成功した場合、WOLFSSL_STACK(STACK_OF(WOLFSSL_X509)と同じ)ポインタを返します。
    \return Null 失敗時。

    \param ctx 解析チェーンを取得する証明書ストアコンテキスト。

    _Example_
    \code
    WOLFSSL_STACK* sk;
    WOLFSSL_X509_STORE_CTX* ctx;
    sk = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    // skがNULLでないか確認してから使用。使用後はskを解放する必要があります
    \endcode

    \sa wolfSSL_sk_X509_free
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief この関数は渡されたWOLFSSL_X509_STORE構造体の動作を変更するためのフラグを受け取ります。使用されるフラグの例としてWOLFSSL_CRL_CHECKがあります。

    \return SSL_SUCCESS フラグの設定時にエラーが発生しなかった場合。
    \return <0 失敗時に負の値が返されます。

    \param str フラグを設定する証明書ストア。
    \param flag 動作のためのフラグ。

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    int ret;
    // strを作成して設定
    ret = wolfSSL_X509_STORE_set_flags(str, WOLFSSL_CRL_CHECKALL);
    if (ret != SSL_SUCCESS) {
    	//ret値を確認してエラーケースを処理する
    }
    \endcode

    \sa wolfSSL_X509_STORE_new
    \sa wolfSSL_X509_STORE_free
*/
int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store,
                                                            unsigned long flag);

/*!
    \ingroup CertsKeys

    \brief この関数は、バイト配列としてエンコードされた証明書の「not before」有効期限を返します。

    \return NULL WOLFSSL_X509構造体がNULLの場合に返されます。
    \return byte notBeforeDataを含むバイトが返されます。

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

    \brief この関数は、バイト配列としてエンコードされた証明書の「not after」有効期限を返します。

    \return NULL WOLFSSL_X509構造体がNULLの場合に返されます。
    \return byte notAfterDataを含むバイトが返されます。

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

    \brief この関数は、WOLFSSL_ASN1_INTEGER値をWOLFSSL_BIGNUM構造体にコピーするために使用されます。

    \return pointer WOLFSSL_ASN1_INTEGER値のコピーに成功すると、WOLFSSL_BIGNUMポインタが返されます。
    \return Null 失敗時にはNullが返されます。

    \param ai コピー元のWOLFSSL_ASN1_INTEGER構造体。
    \param bn 既存のWOLFSSL_BIGNUM構造体にコピーしたい場合は、そのポインタを渡します。オプションとして、これをNULLにすることで新しいWOLFSSL_BIGNUM構造体が作成されます。

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* ai;
    WOLFSSL_BIGNUM* bn;
    // aiを作成
    bn = wolfSSL_ASN1_INTEGER_to_BN(ai, NULL);

    // または既にbnを作成済みで構造体を再利用したい場合
    // wolfSSL_ASN1_INTEGER_to_BN(ai, bn);
    // bnまたは戻り値がNULLでないことを確認
    \endcode

    \sa none
*/
WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
                                       WOLFSSL_BIGNUM *bn);

/*!
    \ingroup Setup

    \brief この関数は、WOLFSSL_CTX構造体内で構築中の内部チェーンに証明書を追加します。

    \return SSL_SUCCESS 証明書の追加に成功した後に返されます。
    \return SSL_FAILURE 証明書のチェーンへの追加に失敗した場合に返されます。

    \param ctx 証明書を追加するWOLFSSL_CTX構造体。
    \param x509 チェーンに追加する証明書。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL_X509* x509;
    int ret;
    // ctxを作成
    ret = wolfSSL_CTX_add_extra_chain_cert(ctx, x509);
    // ret値を確認
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief この関数は、WOLFSSL_CTX構造体からリードアヘッドフラグを取得して返します。

    \return flag 成功時にはリードアヘッドフラグが返されます。
    \return SSL_FAILURE ctxがNULLの場合、SSL_FAILUREが返されます。

    \param ctx リードアヘッドフラグを取得するWOLFSSL_CTX構造体。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    // ctxをセットアップ
    flag = wolfSSL_CTX_get_read_ahead(ctx);
    //flagを確認
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_read_ahead
*/
int  wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief この関数は、WOLFSSL_CTX構造体内のリードアヘッドフラグを設定します。

    \return SSL_SUCCESS ctxのリードアヘッドフラグが設定された場合。
    \return SSL_FAILURE ctxがNULLの場合、SSL_FAILUREが返されます。

    \param ctx リードアヘッドフラグを設定するWOLFSSL_CTX構造体。
    \param v リードアヘッドフラグ。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    int ret;
    // ctxをセットアップ
    ret = wolfSSL_CTX_set_read_ahead(ctx, flag);
    // 戻り値を確認
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_get_read_ahead
*/
int  wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX* ctx, int v);

/*!
    \ingroup Setup

    \brief この関数は、OCSPで使用するオプション引数を設定します。

    \return SSL_FAILURE ctxまたはその証明書マネージャがNULLの場合。
    \return SSL_SUCCESS 正常に設定された場合。

    \param ctx ユーザー引数を設定するWOLFSSL_CTX構造体。
    \param arg ユーザー引数。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // ctxをセットアップ
    ret = wolfSSL_CTX_set_tlsext_status_arg(ctx, data);

    //ret値を確認
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup CertsKeys

    \brief クライアント証明書と秘密鍵を選択するコールバックを設定します。

    この関数は、ハンドシェイク中にクライアント証明書が要求されたときに呼び出されるコールバックをアプリケーションが登録できるようにします。コールバックは、使用する証明書と鍵を選択して提供できます。

    \param ctx WOLFSSL_CTXオブジェクト。
    \param cb クライアント証明書と鍵を選択するコールバック関数。

    \return void

    _Example_
    \code
    int my_client_cert_cb(WOLFSSL *ssl, WOLFSSL_X509 **x509, WOLFSSL_EVP_PKEY **pkey) { ... }
    wolfSSL_CTX_set_client_cert_cb(ctx, my_client_cert_cb);
    \endcode

    \sa wolfSSL_CTX_set_cert_cb
*/
void wolfSSL_CTX_set_client_cert_cb(WOLFSSL_CTX *ctx, client_cert_cb cb);

/*!
    \ingroup CertsKeys

    \brief 汎用証明書セットアップコールバックを設定します。

    この関数は、証明書セットアップ中に呼び出されるコールバックをアプリケーションが登録できるようにします。コールバックは、カスタム証明書選択またはロードロジックを実行できます。

    \param ctx WOLFSSL_CTXオブジェクト。
    \param cb 証明書セットアップ用のコールバック関数。
    \param arg コールバックに渡すユーザー引数。

    \return void

    _Example_
    \code
    int my_cert_setup_cb(WOLFSSL* ssl, void* arg) { ... }
    wolfSSL_CTX_set_cert_cb(ctx, my_cert_setup_cb, NULL);
    \endcode

    \sa wolfSSL_CTX_set_client_cert_cb
*/
void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx, CertSetupCallback cb, void *arg);

/*!
    \ingroup OCSP

    \brief OCSPステータス要求(OCSPステープリング)を処理するために使用されるコールバックを設定します。

    この関数は、TLSハンドシェイク中にOCSPステータス要求を受信したときに呼び出されるコールバックをアプリケーションが登録できるようにします。コールバックは、ハンドシェイクにステープルされるOCSPレスポンスを提供できます。このAPIはサーバー側でのみ有用です。

    \param ctx WOLFSSL_CTXオブジェクト。
    \param cb OCSPステータス要求を処理するコールバック関数。

    \return SSL_SUCCESS 成功時、それ以外の場合はSSL_FAILURE。

    _Example_
    \code
    int my_ocsp_status_cb(WOLFSSL* ssl, void* arg) { ... }
    wolfSSL_CTX_set_tlsext_status_cb(ctx, my_ocsp_status_cb);
    \endcode

    \sa wolfSSL_CTX_get_tlsext_status_cb
    \sa wolfSSL_CTX_set_tlsext_status_arg
*/
int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb);

/*!
    \ingroup OCSP

    \brief コンテキストに現在設定されているOCSPステータスコールバックを取得します。

    \param ctx WOLFSSL_CTXオブジェクト。
    \param cb コールバック関数を受け取るポインタ。

    \return SSL_SUCCESS 成功時、それ以外の場合はSSL_FAILURE。

    \sa wolfSSL_CTX_set_tlsext_status_cb
*/
int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb);

/*!
    \ingroup OCSP

    \brief OCSPステータスコールバックに渡される引数を設定します。

    \param ctx WOLFSSL_CTXオブジェクト。
    \param arg コールバックに渡すユーザー引数。

    \return SSL_SUCCESS 成功時、それ以外の場合はSSL_FAILURE。

    \sa wolfSSL_CTX_set_tlsext_status_cb
*/
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup OCSP

    \brief ピアに送信(ステープル)されるOCSPレスポンスを取得します。

    \param ssl WOLFSSLセッション。
    \param resp レスポンスバッファを受け取るポインタ。

    \return Length レスポンスの長さ、またはエラー時は負の値。

    \sa wolfSSL_set_tlsext_status_ocsp_resp
*/
long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char **resp);

/*!
    \ingroup OCSP

    \brief ピアに送信(ステープル)されるOCSPレスポンスを設定します。

    respのバッファはwolfSSLによって所有され、wolfSSLによって解放されます。アプリケーションは、この関数を呼び出した後、バッファを解放してはいけません。

    \param ssl WOLFSSLセッション。
    \param resp レスポンスバッファへのポインタ。
    \param len レスポンスバッファの長さ。

    \return SSL_SUCCESS 成功時、それ以外の場合はSSL_FAILURE。

    \sa wolfSSL_get_tlsext_status_ocsp_resp
*/
long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char *resp, int len);

/*!
    \ingroup OCSP

    \brief TLSマルチ証明書チェーン用の複数のOCSPレスポンスを設定します。

    respのバッファはwolfSSLによって所有され、wolfSSLによって解放されます。アプリケーションは、この関数を呼び出した後、バッファを解放してはいけません。

    \param ssl WOLFSSLセッション。
    \param resp レスポンスバッファへのポインタ。
    \param len レスポンスバッファの長さ。
    \param idx 証明書チェーンのインデックス。

    \return SSL_SUCCESS 成功時、それ以外の場合はSSL_FAILURE。
*/
int wolfSSL_set_tlsext_status_ocsp_resp_multi(WOLFSSL* ssl, unsigned char *resp, int len, word32 idx);

/*!
    \ingroup OCSP

    \brief OCSPステータスレスポンスを検証するコールバックを設定します。

    OCSP検証中にピアの証明書チェーンにアクセスできるようにするため、SESSION_CERTSを有効にすることを推奨します。

    \param ctx WOLFSSL_CTXオブジェクト。
    \param cb コールバック関数。
    \param cbArg コールバックに渡すユーザー引数。

    \return void

    _Example_
    \code
    void my_ocsp_verify_cb(WOLFSSL* ssl, int err, byte* resp, word32 respSz, word32 idx, void* arg)
    {
        (void)arg;
        if (err == 0 && staple && stapleSz > 0) {
            printf("Client: OCSP staple received, size=%u\n", stapleSz);
            return 0;
        }
        // err != 0の場合、手動OCSPステープル検証
        if (err != 0 && staple && stapleSz > 0) {
            WOLFSSL_CERT_MANAGER* cm = NULL;
            DecodedCert cert;
            byte certInit = 0;
            WOLFSSL_OCSP* ocsp = NULL;
            WOLFSSL_X509_CHAIN* peerCerts;
            int i;

            cm = wolfSSL_CertManagerNew();
            if (cm == NULL)
                goto cleanup;
            if (wolfSSL_CertManagerLoadCA(cm, CA_CERT, NULL) != WOLFSSL_SUCCESS)
                goto cleanup;

            peerCerts = wolfSSL_get_peer_chain(ssl);
            if (peerCerts == NULL || wolfSSL_get_chain_count(peerCerts) <= (int)idx)
                goto cleanup;

            for (i = idx + 1; i < wolfSSL_get_chain_count(peerCerts); i++) {
                if (wolfSSL_CertManagerLoadCABuffer(cm, wolfSSL_get_chain_cert(peerCerts, i),
                        wolfSSL_get_chain_length(peerCerts, i), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
                    goto cleanup;
            }

            wc_InitDecodedCert(&cert, wolfSSL_get_chain_cert(peerCerts, idx), wolfSSL_get_chain_length(peerCerts, idx), NULL);
            certInit = 1;
            if (wc_ParseCert(&cert, CERT_TYPE, VERIFY, cm) != 0)
                goto cleanup;
            if ((ocsp = wc_NewOCSP(cm)) == NULL)
                goto cleanup;
            if (wc_CheckCertOcspResponse(ocsp, &cert, staple, stapleSz, NULL) != 0)
                goto cleanup;

            printf("Client: Manual OCSP staple verification succeeded for idx=%u\n", idx);
            err = 0;
    cleanup:
            wc_FreeOCSP(ocsp);
            if (certInit)
                wc_FreeDecodedCert(&cert);
            wolfSSL_CertManagerFree(cm);
            if (err == 0)
                return 0;
            printf("Client: Manual OCSP staple verification failed for idx=%u\n", idx);
        }
        printf("Client: OCSP staple verify error=%d\n", err);
        return err;
    }
    wolfSSL_CTX_set_ocsp_status_verify_cb(ctx, my_ocsp_verify_cb, NULL);
    \endcode
*/
void wolfSSL_CTX_set_ocsp_status_verify_cb(WOLFSSL_CTX* ctx, ocspVerifyStatusCb cb, void* cbArg);

/*!
    \ingroup Setup

    \brief この関数は、PRFコールバックに渡されるオプション引数を設定します。

    \return SSL_FAILURE ctxがNULLの場合。
    \return SSL_SUCCESS 正常に設定された場合。

    \param ctx ユーザ引数を設定するWOLFSSL_CTX構造体。
    \param arg ユーザ引数。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // ctxをセットアップ
    ret = wolfSSL_CTX_set_tlsext_opaques_prf_input_callback_arg(ctx, data);
    //ret値を確認
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(
        WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup Setup

    \brief この関数は、ssl内のオプションマスクを設定します。有効なオプションには、SSL_OP_ALL、SSL_OP_COOKIE_EXCHANGE、SSL_OP_NO_SSLv2、SSL_OP_NO_SSLv3、SSL_OP_NO_TLSv1、SSL_OP_NO_TLSv1_1、SSL_OP_NO_TLSv1_2、SSL_OP_NO_COMPRESSIONがあります。

    \return val sslに格納されている更新されたオプションマスク値を返します。

    \param s オプションマスクを設定するWOLFSSL構造体。
    \param op この関数は、ssl内のオプションマスクを設定します。有効なオプションには以下が含まれます:
    SSL_OP_ALL
    SSL_OP_COOKIE_EXCHANGE
    SSL_OP_NO_SSLv2
    SSL_OP_NO_SSLv3
    SSL_OP_NO_TLSv1
    SSL_OP_NO_TLSv1_1
    SSL_OP_NO_TLSv1_2
    SSL_OP_NO_COMPRESSION

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask = SSL_OP_NO_TLSv1
    mask  = wolfSSL_set_options(ssl, mask);
    // maskを確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_get_options
*/
long wolfSSL_set_options(WOLFSSL *s, long op);

/*!
    \ingroup Setup

    \brief この関数は、現在のオプションマスクを返します。

    \return val sslに格納されているマスク値を返します。

    \param ssl オプションマスクを取得するWOLFSSL構造体。

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask  = wolfSSL_get_options(ssl);
    // maskを確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_set_options
*/
long wolfSSL_get_options(const WOLFSSL *ssl);

/*!
    \ingroup Setup

    \brief これは、渡されるデバッグ引数を設定するために使用されます。

    \return SSL_SUCCESS 引数の設定に成功した場合。
    \return SSL_FAILURE NULLのsslが渡された場合。

    \param ssl 引数を設定するWOLFSSL構造体。
    \param arg 使用する引数。

    _Example_
    \code
    WOLFSSL* ssl;
    void* args;
    int ret;
    // sslオブジェクトを作成
    ret  = wolfSSL_set_tlsext_debug_arg(ssl, args);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_set_tlsext_debug_arg(WOLFSSL *ssl, void *arg);

/*!
    \ingroup openSSL

    \brief この関数は、クライアントアプリケーションがサーバにOCSPステータスレスポンス(OCSPステープリングとも呼ばれます)を返送するよう要求する際に呼び出されます。現在、サポートされている唯一のタイプはTLSEXT_STATUSTYPE_ocspです。

    \return 1 成功時。
    \return 0 エラー時。

    \param s SSL_new()関数によって作成されたWOLFSSL構造体へのポインタ。
    \param type TLSEXT_STATUSTYPE_ocspのみがサポートされているSSL拡張タイプ。

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

    \brief これは、ピアの証明書の検証を試みた後の結果を取得するために使用されます。

    \return X509_V_OK 検証が成功した場合。
    \return SSL_FAILURE NULLのsslが渡された場合。

    \param ssl 検証結果を取得するWOLFSSL構造体。

    _Example_
    \code
    WOLFSSL* ssl;
    long ret;
    // ハンドシェイクを試行/完了
    ret  = wolfSSL_get_verify_result(ssl);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_get_verify_result(const WOLFSSL *ssl);

/*!
    \ingroup Debug

    \brief この関数は、wolfSSL_get_error()によって返されたエラーコードを、より人間が読みやすいエラー文字列に変換し、その文字列を出力ファイルfpに出力します。errはwolfSSL_get_error()によって返されたエラーコードであり、fpはエラー文字列が配置されるファイルです。

    \return none 戻り値なし。

    \param fp 人間が読みやすいエラー文字列が書き込まれる出力ファイル。
    \param err wolfSSL_get_error()によって返されたエラーコード。

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

    \brief この関数は、提供されたコールバックを使用してエラーレポートを処理します。コールバック関数は、各エラー行に対して実行されます。文字列、長さ、およびユーザデータがコールバックパラメータに渡されます。

    \return none 戻り値なし。

    \param cb コールバック関数。
    \param u コールバック関数に渡すユーザデータ。

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
    \brief この関数は、WOLFSSL_CTX構造体のclient_psk_cbメンバを設定します。

    \return none 戻り値なし。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param cb WOLFSSL_CTX構造体に格納される関数ポインタであるwc_psk_client_callback。戻り値は、成功時には鍵の長さ、エラー時にはゼロです。
    unsigned int (*wc_psk_client_callback)
    PSKクライアントコールバックのパラメータ:
    WOLFSSL* ssl - wolfSSL構造体へのポインタ
    const char* hint - ユーザへのヒントを表示するために使用できる格納された文字列。
    char* identity - IDがここに格納されます。
    unsigned int id_max_len - IDバッファのサイズ。
    unsigned char* key - 鍵がここに格納されます。
    unsigned int key_max_len - 鍵の最大サイズ。

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
    \brief PSKクライアント側コールバックを設定します。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb wc_psk_client_callback型への関数ポインタ。戻り値は、成功時には鍵の長さ、エラー時にはゼロです。
    unsigned int (*wc_psk_client_callback)
    PSKクライアントコールバックのパラメータ:
    WOLFSSL* ssl - wolfSSL構造体へのポインタ
    const char* hint - ユーザへのヒントを表示するために使用できる格納された文字列。
    char* identity - IDがここに格納されます。
    unsigned int id_max_len - IDバッファのサイズ。
    unsigned char* key - 鍵がここに格納されます。
    unsigned int key_max_len - 鍵の最大サイズ。

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
            // コールバックを設定できませんでした。
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

    \brief この関数は、PSKアイデンティティヒントを返します。

    \return pointer WOLFSSL構造体のarraysメンバに格納されていた値へのconst char型ポインタが返されます。
    \return NULL WOLFSSLまたはArrays構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* idHint;
    ...
    idHint = wolfSSL_get_psk_identity_hint(ssl);
    if(idHint){
    	// ヒントが取得されました。
    	return idHint;
    } else {
    	// ヒントの取得に成功しませんでした。
    }
    \endcode

    \sa wolfSSL_get_psk_identity
*/
const char* wolfSSL_get_psk_identity_hint(const WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief この関数は、Arrays構造体のclient_identityメンバへの定数ポインタを返します。

    \return string Arrays構造体のclient_identityメンバの文字列値。
    \return NULL WOLFSSL構造体がNULL、またはWOLFSSL構造体のArraysメンバがNULLの場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);    const char* pskID;
    ...
    pskID = wolfSSL_get_psk_identity(ssl);

    if(pskID == NULL){
	    // pskIDに値がありません
    }
    \endcode

    \sa wolfSSL_get_psk_identity_hint
    \sa wolfSSL_use_psk_identity_hint
*/
const char* wolfSSL_get_psk_identity(const WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief この関数は、hint引数をWOLFSSL_CTX構造体のserver_hintメンバに格納します。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param hint WOLFSSL_CTX構造体にコピーされる定数charポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    const char* hint;
    int ret;
    …
    ret = wolfSSL_CTX_use_psk_identity_hint(ctx, hint);
    if(ret == SSL_SUCCESS){
    	// 関数は成功しました
	return ret;
    } else {
    	// 失敗ケース
    }
    \endcode

    \sa wolfSSL_use_psk_identity_hint
*/
int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint);

/*!
    \ingroup CertsKeys

    \brief この関数は、hint引数をWOLFSSL構造体内のArrays構造体のserver_hintメンバに格納します。

    \return SSL_SUCCESS hintがWOLFSSL構造体に正常に格納された場合に返されます。
    \return SSL_FAILURE WOLFSSLまたはArrays構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param hint メモリに保存されるヒントを保持する定数文字ポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* hint;
    ...
    if(wolfSSL_use_psk_identity_hint(ssl, hint) != SSL_SUCCESS){
    	// 失敗ケースを処理
    }
    \endcode

    \sa wolfSSL_CTX_use_psk_identity_hint
*/
int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint);

/*!
    \brief この関数は、WOLFSSL_CTX構造体にサーバ側のpskコールバックを設定します。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb コールバック用の関数ポインタで、WOLFSSL_CTX構造体に格納されます。戻り値は成功時は鍵の長さ、エラー時は0です。
    unsigned int (*wc_psk_server_callback)
    PSKサーバコールバックのパラメータ
    WOLFSSL* ssl - wolfSSL構造体へのポインタ
    char* identity - IDがここに格納されます
    unsigned char* key - 鍵がここに格納されます
    unsigned int key_max_len - 鍵の最大サイズ

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // 関数本体
    }
    …
    if(ctx != NULL){
        wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    } else {
    	// CTXオブジェクトが適切に初期化されませんでした
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
    \brief WOLFSSL構造体のoptionsメンバを設定することにより、サーバ側のpskコールバックを設定します。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb コールバック用の関数ポインタで、WOLFSSL構造体に格納されます。戻り値は成功時は鍵の長さ、エラー時は0です。
    unsigned int (*wc_psk_server_callback)
    PSKサーバコールバックのパラメータ
    WOLFSSL* ssl - wolfSSL構造体へのポインタ
    char* identity - IDがここに格納されます
    unsigned char* key - 鍵がここに格納されます
    unsigned int key_max_len - 鍵の最大サイズ


    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // 関数本体
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
    \brief WOLFSSL構造体のoptionsメンバにPSKユーザコンテキストを設定します。

    \return WOLFSSL_SUCCESSまたはWOLFSSL_FAILURE

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param psk_ctx ユーザPSKコンテキストへのvoidポインタ。

    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_set_psk_callback_ctx(WOLFSSL* ssl, void* psk_ctx);

/*!
    \brief WOLFSSL_CTX構造体にPSKユーザコンテキストを設定します。

    \return WOLFSSL_SUCCESSまたはWOLFSSL_FAILURE

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param psk_ctx ユーザPSKコンテキストへのvoidポインタ。

    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_CTX_set_psk_callback_ctx(WOLFSSL_CTX* ctx, void* psk_ctx);

/*!
    \brief WOLFSSL構造体のoptionsメンバからPSKユーザコンテキストを取得します。

    \return ユーザPSKコンテキストへのvoidポインタ。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl);

/*!
    \brief WOLFSSL_CTX構造体からPSKユーザコンテキストを取得します。

    \return ユーザPSKコンテキストへのvoidポインタ。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
*/
void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief この関数は、コンパイル時にHAVE_ANONが定義されている場合、CTX構造体のhavAnonメンバを有効にします。

    \return SSL_SUCCESS 関数が正常に実行され、CTXのhaveAnnonメンバが1に設定された場合に返されます。
    \return SSL_FAILURE CTX構造体がNULLの場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    #ifdef HAVE_ANON
	if(cipherList == NULL){
	    wolfSSL_CTX_allow_anon_cipher(ctx);
	    if(wolfSSL_CTX_set_cipher_list(ctx, "ADH_AES128_SHA") != SSL_SUCCESS){
		    // 失敗ケース
	    }
    }
    #endif
    \endcode

    \sa none
*/
int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief wolfSSLv23_server_method()関数は、アプリケーションがサーバであり、SSL 3.0からTLS 1.3までのプロトコルバージョンで接続するクライアントをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいWOLFSSL_METHOD構造体のためのメモリを割り当て、初期化します。

    \return pointer 成功時、新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return Failure XMALLOCを呼び出す際にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    \param none パラメータなし。

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv23_server_method();
    if (method == NULL) {
    	// メソッドを取得できませんでした
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

    \brief これは、WOLFSSL構造体の内部エラー状態を取得するために使用されます。

    \return wolfssl_error sslエラー状態を返します。通常は負の値です。
    \return BAD_FUNC_ARG sslがNULLの場合。

    \return ssl 状態を取得するWOLFSSL構造体。

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // sslオブジェクトを作成
    ret  = wolfSSL_state(ssl);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int  wolfSSL_state(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief この関数は、ピアの証明書を取得します。

    \return pointer 存在する場合、WOLFSSL_X509構造体のpeerCertメンバへのポインタ。
    \return 0 ピア証明書発行者のサイズが定義されていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    WOLFSSL_X509* peerCert = wolfSSL_get_peer_certificate(ssl);

    if(peerCert){
    	// ピア証明書へのポインタpeerCertがあります
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);

/*!
    \ingroup Debug

    \brief この関数は、wolfSSL_get_error()を呼び出してSSL_ERROR_WANT_READが返される場合と同様です。基礎となるエラー状態がSSL_ERROR_WANT_READの場合、この関数は1を返し、それ以外の場合は0を返します。

    \return 1 wolfSSL_get_error()がSSL_ERROR_WANT_READを返す場合。基礎となるI/Oに読み取り可能なデータがあります。
    \return 0 SSL_ERROR_WANT_READエラー状態がない場合。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_want_read(ssl);
    if (ret == 1) {
    	// 基礎となるI/Oに読み取り可能なデータがあります(SSL_ERROR_WANT_READ)
    }
    \endcode

    \sa wolfSSL_want_write
    \sa wolfSSL_get_error
*/
int wolfSSL_want_read(WOLFSSL*);

/*!
    \ingroup Debug

    \brief この関数は、wolfSSL_get_error()を呼び出してSSL_ERROR_WANT_WRITEが返される場合と同様です。基礎となるエラー状態がSSL_ERROR_WANT_WRITEの場合、この関数は1を返し、それ以外の場合は0を返します。

    \return 1 wolfSSL_get_error()がSSL_ERROR_WANT_WRITEを返す場合。基礎となるSSL接続で進行するために、基礎となるI/Oにデータを書き込む必要があります。
    \return 0 SSL_ERROR_WANT_WRITEエラー状態がない場合。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_want_write(ssl);
    if (ret == 1) {
    	// 基礎となるI/Oにデータを書き込む必要があります(SSL_ERROR_WANT_WRITE)
    }
    \endcode

    \sa wolfSSL_want_read
    \sa wolfSSL_get_error
*/int wolfSSL_want_write(WOLFSSL*);

/*!
    \ingroup Setup

    \brief wolfSSLはデフォルトでピア証明書の有効な日付範囲と検証済み署名をチェックします。wolfSSL_connect()またはwolfSSL_accept()の前にこの関数を呼び出すと、実行するチェックのリストにドメイン名チェックが追加されます。dnは、受信したピア証明書に対してチェックするドメイン名を保持します。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE メモリエラーが発生した場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param dn 受信したピア証明書に対してチェックするドメイン名。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    char* domain = (char*) "www.yassl.com";
    ...

    ret = wolfSSL_check_domain_name(ssl, domain);
    if (ret != SSL_SUCCESS) {
       // ドメイン名チェックの有効化に失敗しました
    }
    \endcode

    \sa none
*/
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn);

/*!
    \ingroup TLS

    \brief 使用するためにwolfSSLライブラリを初期化します。アプリケーションごとに1回、ライブラリへの他の呼び出しの前に呼び出す必要があります。

    \return SSL_SUCCESS 成功した場合に返されます。
    \return BAD_MUTEX_E 返される可能性のあるエラーです。
    \return WC_INIT_E wolfCrypt初期化エラーが返されます。

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
	    wolfSSLライブラリの初期化に失敗しました
    }

    \endcode

    \sa wolfSSL_Cleanup
*/
int wolfSSL_Init(void);

/*!
    \ingroup TLS

    \brief wolfSSLライブラリをこれ以上使用しないように初期化を解除します。呼び出す必要はありませんが、ライブラリが使用したリソースを解放します。

    \return SSL_SUCCESS エラーなしで返されます。
    \return BAD_MUTEX_E mutexエラーが返されます。

    _Example_
    \code
    wolfSSL_Cleanup();
    \endcode

    \sa wolfSSL_Init
*/
int wolfSSL_Cleanup(void);

/*!
    \ingroup IO

    \brief この関数は現在のライブラリバージョンを返します。

    \return LIBWOLFSSL_VERSION_STRING バージョンを定義するconst charポインタ。

    \param none パラメータなし。

    _Example_
    \code
    char version[MAXSIZE];
    version = wolfSSL_KeepArrays();
    …
    if(version != ExpectedVersion){
	    // 不一致ケースを処理
    }
    \endcode

    \sa word32_wolfSSL_lib_version_hex
*/
const char* wolfSSL_lib_version(void);

/*!
    \ingroup IO

    \brief この関数は現在のライブラリバージョンを16進表記で返します。

    \return LILBWOLFSSL_VERSION_HEX wolfssl/version.hで定義された16進バージョンを返します。

    \param none パラメータなし。

    _Example_
    \code
    word32 libV;
    libV = wolfSSL_lib_version_hex();

    if(libV != EXPECTED_HEX){
	    // 予期しない値の処理方法
    } else {
	    // libVの期待される結果
    }
    \endcode

    \sa wolfSSL_lib_version
*/
word32 wolfSSL_lib_version_hex(void);

/*!
    \ingroup IO

    \brief SSLメソッドの側面に基づいて実際の接続または受け入れを実行します。クライアント側から呼び出された場合はwolfSSL_connect()が実行され、サーバー側から呼び出された場合はwolfSSL_accept()が実行されます。

    \return SSL_SUCCESS 成功した場合に返されます(注:古いバージョンでは0が返されます)。
    \return SSL_FATAL_ERROR 基礎となる呼び出しがエラーになった場合に返されます。特定のエラーコードを取得するにはwolfSSL_get_error()を使用してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int ret = SSL_FATAL_ERROR;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_negotiate(ssl);
    if (ret == SSL_FATAL_ERROR) {
    	// SSL確立に失敗しました
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

    \brief SSL接続で圧縮を使用する機能をオンにします。両側で圧縮をオンにする必要があります。そうでない場合、圧縮は使用されません。zlibライブラリが実際のデータ圧縮を実行します。ライブラリにコンパイルするには、configureシステムで--with-libzを使用し、HAVE_LIBZを定義してください。送信前にデータを圧縮すると送受信されるメッセージの実際のサイズは減少しますが、圧縮によって節約されるデータの量は、最も遅いネットワークを除いて、生データで送信するよりも解析に時間がかかることに注意してください。

    \return SSL_SUCCESS 成功時。
    \return NOT_COMPILED_IN 圧縮サポートがライブラリにビルドされていない場合に返されます。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_compression(ssl);
    if (ret == SSL_SUCCESS) {
    	// SSLセッションの圧縮を正常に有効化しました
    }
    \endcode

    \sa none
*/
int wolfSSL_set_compression(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数はSSLセッションのタイムアウト値を秒単位で設定します。

    \return SSL_SUCCESS セッションの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG sslがNULLの場合に返されます。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param to SSLセッションタイムアウトの設定に使用される秒単位の値。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_timeout(ssl, 500);
    if (ret != SSL_SUCCESS) {
    	// セッションタイムアウト値の設定に失敗しました
    }
    ...
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
int wolfSSL_set_timeout(WOLFSSL* ssl, unsigned int to);

/*!
    \ingroup Setup

    \brief この関数は、指定されたSSLコンテキストのSSLセッションのタイムアウト値を秒単位で設定します。

    \return WOLFSSL_ERROR_CODE_OPENSSLが定義されている場合、成功時に以前のタイムアウト値が返されます。定義されていない場合、SSL_SUCCESSが返されます。
    \return BAD_FUNC_ARG 入力コンテキスト(ctx)がnullの場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param to セッションタイムアウト値(秒単位)。

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    ret = wolfSSL_CTX_set_timeout(ctx, 500);
    if (ret != SSL_SUCCESS) {
	    // セッションタイムアウト値の設定に失敗しました
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

    \brief ピアの証明書チェーンを取得します。

    \return chain 成功した場合、呼び出しはピアの証明書チェーンを返します。
    \return 0 無効なWOLFSSLポインタが関数に渡された場合に返されます。

    \param ssl 有効なWOLFSSL構造体へのポインタ。

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

    \brief ピアの証明書チェーン数を取得します。

    \return Success 成功した場合、呼び出しはピアの証明書チェーン数を返します。
    \return 0 無効なchainポインタが関数に渡された場合に返されます。

    \param chain 有効なWOLFSSL_X509_CHAIN構造体へのポインタ。

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

    \brief インデックス(idx)におけるピアのASN1.DER証明書の長さをバイト単位で取得します。

    \return Success 成功した場合、呼び出しはインデックスによるピアの証明書の長さをバイト単位で返します。
    \return 0 無効なchainポインタが関数に渡された場合に返されます。

    \param chain 有効なWOLFSSL_X509_CHAIN構造体へのポインタ。
    \param idx チェーンの開始インデックス。

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

    \brief インデックス(idx)におけるピアのASN1.DER証明書を取得します。

    \return Success 成功した場合、呼び出しはインデックスによるピアの証明書を返します。
    \return 0 無効なchainポインタが関数に渡された場合に返されます。

    \param chain 有効なWOLFSSL_X509_CHAIN構造体へのポインタ。
    \param idx チェーンの開始インデックス。

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

    \brief この関数は証明書チェーンからインデックス(idx)にあるピアのwolfSSL_X509_certificateを取得します。

    \return pointer WOLFSSL_X509構造体へのポインタを返します。

    \param chain 動的メモリを使用しないSESSION_CACHEに使用されるWOLFSSL_X509_CHAINへのポインタ。
    \param idx WOLFSSL_X509証明書のインデックス。

    返されたメモリをwolfSSL_FreeX509()を呼び出して解放することはユーザーの責任です。

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = &session->chain;
    int idx = 999; // idxを設定
    ...
    WOLFSSL_X509_CHAIN ptr;
    prt = wolfSSL_get_chain_X509(chain, idx);

    if(ptr != NULL){
        // ptrは指定されたインデックスの証明書を含みます
        wolfSSL_FreeX509(ptr);
    } else {
        // ptrはNULLです
    }
    \endcode

    \sa InitDecodedCert
    \sa ParseCertRelative
    \sa CopyDecodedToX509
*/
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup openSSL

    \brief インデックス(idx)におけるピアのPEM証明書を取得します。

    \return Success 成功した場合、呼び出しはインデックスによるピアの証明書を返します。
    \return 0 無効なchainポインタが関数に渡された場合に返されます。

    \param chain 有効なWOLFSSL_X509_CHAIN構造体へのポインタ。    \param idx チェーンの開始インデックス。

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

    \brief セッションIDを取得します。セッションIDは常に32バイト長です。

    \return id セッションID。

    \param session 有効なwolfsslセッションへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa SSL_get_session
*/
const unsigned char* wolfSSL_get_sessionID(const WOLFSSL_SESSION* s);

/*!
    \ingroup openSSL

    \brief ピアの証明書シリアル番号を取得します。シリアル番号バッファ(in)は少なくとも32バイト長であり、入力として*inOutSz引数として提供される必要があります。関数を呼び出した後、*inOutSzにはinバッファに書き込まれた実際の長さ(バイト単位)が保持されます。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 不正な関数引数が検出された場合に返されます。

    \param in シリアル番号バッファで、少なくとも32バイト長である必要があります。
    \param inOutSz inバッファに書き込まれた実際の長さ(バイト単位)を保持します。

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

    \brief 証明書からサブジェクトのコモンネームを返します。

    \return NULL x509構造体がnullの場合に返されます。
    \return string 成功時にはサブジェクトのコモンネームの文字列表現が返されます。

    \param x509 証明書情報を含むWOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509Cn = wolfSSL_X509_get_subjectCN(x509);
    if(x509Cn == NULL){
	    // NULLケースを処理
    } else {
	    // x509Cnにはコモンネームが含まれる
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

    \brief この関数は、WOLFSSL_X509構造体内のDERエンコードされた証明書を取得します。

    \return buffer この関数は、DerBuffer構造体のbufferメンバを返します。これはbyte型です。
    \return NULL x509またはoutSzパラメータがNULLの場合に返されます。

    \param x509 証明書情報を含むWOLFSSL_X509構造体へのポインタ。
    \param outSz WOLFSSL_X509構造体のderBufferメンバの長さ。

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    int* outSz; // 初期化
    ...
    byte* x509Der = wolfSSL_X509_get_der(x509, outSz);
    if(x509Der == NULL){
	    // 失敗ケース、パラメータの1つがNULLだった
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

    \brief この関数は、x509がNULLであるかどうかをチェックし、そうでない場合はx509構造体のnotAfterメンバを返します。

    \return pointer x509構造体のnotAfterメンバへのASN1_TIMEを持つ構造体へのポインタ。
    \return NULL x509オブジェクトがNULLの場合に返されます。

    \param x509 WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    ...
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notAfter(x509);
    if(notAfter == NULL){
        // 失敗ケース、x509オブジェクトがnull
    }
    \endcode

    \sa wolfSSL_X509_get_notBefore
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief この関数は、X509証明書のバージョンを取得します。

    \return 0 x509構造体がNULLの場合に返されます。
    \return version x509構造体に格納されているバージョンが返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509;
    int version;
    ...
    version = wolfSSL_X509_version(x509);
    if(!version){
	    // 関数は0を返した、失敗ケース
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

    \brief NO_STDIO_FILESYSTEMが定義されている場合、この関数はヒープメモリを割り当て、WOLFSSL_X509構造体を初期化し、そのポインタを返します。

    \return *WOLFSSL_X509 関数が正常に実行された場合、WOLFSSL_X509構造体ポインタが返されます。
    \return NULL XFTELLマクロの呼び出しが負の値を返した場合。

    \param x509 WOLFSSL_X509ポインタへのポインタ。
    \param file FILEへのポインタである定義された型。

    _Example_
    \code
    WOLFSSL_X509* x509a = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    WOLFSSL_X509** x509 = x509a;
    XFILE file;  // (struct fs_file*にマップされる)
    ...
    WOLFSSL_X509* newX509 = wolfSSL_X509_d2i_fp(x509, file);
    if(newX509 == NULL){
	    // 関数はNULLを返した
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

    \brief この関数は、x509証明書をメモリにロードします。

    \return pointer 正常に実行されると、WOLFSSL_X509構造体へのポインタが返されます。
    \return NULL 証明書を書き込むことができなかった場合に返されます。

    \param fname ロードする証明書ファイル。
    \param format 証明書のフォーマット。

    _Example_
    \code
    #define cliCert    "certs/client-cert.pem"
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

    \brief この関数は、x509構造体からデバイスタイプをバッファにコピーします。

    \return pointer x509構造体からデバイスタイプを保持するバイトポインタが返されます。
    \return NULL バッファサイズがNULLの場合に返されます。

    \param x509 WOLFSSL_X509_new()で作成されたWOLFSSL_X509構造体へのポインタ。
    \param in デバイスタイプ(バッファ)を保持するバイト型へのポインタ。
    \param inOutSz パラメータinOutSzまたはx509構造体のdeviceTypeSzメンバのいずれか小さい方。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    byte* in;
    int* inOutSz;
    ...
    byte* deviceType = wolfSSL_X509_get_device_type(x509, in, inOutSz);

    if(!deviceType){
	    // 失敗ケース、NULLが返された
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

    \brief この関数は、WOLFSSL_X509構造体のhwTypeメンバをバッファにコピーします。

    \return byte 関数は、以前にWOLFSSL_X509構造体のhwTypeメンバに保持されていたデータのバイト型を返します。
    \return NULL inOutSzがNULLの場合に返されます。

    \param x509 証明書情報を含むWOLFSSL_X509構造体へのポインタ。
    \param in バッファを表すbyte型へのポインタ。
    \param inOutSz バッファのサイズを表すint型へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509;  // X509証明書
    byte* in;  // バッファを初期化
    int* inOutSz;  // バッファのサイズを保持
    ...
    byte* hwType = wolfSSL_X509_get_hw_type(x509, in, inOutSz);

    if(hwType == NULL){
	    // 失敗ケース、関数はNULLを返した
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

    \brief この関数は、x509オブジェクトのhwSerialNumメンバを返します。

    \return pointer 関数は、x509オブジェクトからロードされたシリアル番号を含むinバッファへのバイトポインタを返します。

    \param x509 証明書情報を含むWOLFSSL_X509構造体へのポインタ。
    \param in コピー先のバッファへのポインタ。
    \param inOutSz バッファのサイズへのポインタ。

    _Example_
    \code
    char* serial;
    byte* in;
    int* inOutSz;
    WOLFSSL_X509 x509;
    ...
    serial = wolfSSL_X509_get_hw_serial_number(x509, in, inOutSz);

    if(serial == NULL || serial <= 0){
    	// 失敗ケース
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

    \brief この関数はクライアント側で呼び出され、ピアの証明書チェーンを取得するのに十分な長さだけサーバーとのSSL/TLSハンドシェイクを開始します。この関数が呼び出されるとき、基礎となる通信チャネルはすでに設定されています。wolfSSL_connect_cert()は、ブロッキングI/Oと非ブロッキングI/Oの両方で動作します。基礎となるI/Oが非ブロッキングの場合、wolfSSL_connect_cert()は、基礎となるI/OがwolfSSL_connect_cert()がハンドシェイクを続行するために必要な処理を満たせないときに戻ります。この場合、wolfSSL_get_error()の呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかを生成します。呼び出しプロセスは、基礎となるI/Oが準備できたときにwolfSSL_connect_cert()の呼び出しを繰り返す必要があり、wolfSSLは中断した場所から再開します。非ブロッキングソケットを使用する場合、何もする必要はありませんが、select()を使用して必要な条件をチェックできます。基礎となるI/OがブロッキングI/Oの場合、wolfSSL_connect_cert()はピアの証明書チェーンが受信されたときにのみ戻ります。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE SSLセッションパラメータがNULLの場合に返されます。
    \return SSL_FATAL_ERROR エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出してください。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

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
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept
*/int  wolfSSL_connect_cert(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief wolfSSL_d2i_PKCS12_bio(d2i_PKCS12_bio)は、WOLFSSL_BIOからWC_PKCS12構造体へPKCS12情報をコピーします。情報は、構造体内でコンテンツ情報のリストとして分割され、オプションのMAC情報を保持する構造体も含まれます。情報がWC_PKCS12構造体内でチャンク(ただし復号されていない)に分割された後、呼び出すことによって解析および復号できます。

    \return WC_PKCS12 WC_PKCS12構造体へのポインタ。
    \return Failure 関数が失敗した場合、NULLを返します。

    \param bio PKCS12バッファを読み取るWOLFSSL_BIO構造体。
    \param pkcs12 作成された新しいPKCS12構造体用のWC_PKCS12構造体ポインタ。NULLでも可。

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bioはPKCS12ファイルを読み込みます。
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, "a password", &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //cert、pkey、およびオプションでcertsスタックを使用します。
    \endcode

    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12** pkcs12);

/*!
    \ingroup openSSL

    \brief wolfSSL_i2d_PKCS12_bio(i2d_PKCS12_bio)は、WC_PKCS12構造体からWOLFSSL_BIOへ証明書情報をコピーします。

    \return 1 成功時。
    \return Failure 0。

    \param bio PKCS12バッファを書き込むWOLFSSL_BIO構造体。
    \param pkcs12 入力としてのPKCS12構造体用のWC_PKCS12構造体。

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
    //DERファイルを内部構造に変換します。
    wc_d2i_PKCS12(buffer, bytes, pkcs12);
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    //PKCS12構造体をbioに変換します。
    wolfSSL_i2d_PKCS12_bio(bio, pkcs12);
    wc_PKCS12_free(pkcs)
    //bioを使用します。
    \endcode

    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12* pkcs12);

/*!
    \ingroup openSSL

    \brief PKCS12は、configureコマンドに--enable-opensslextraを追加することで有効にできます。復号にトリプルDESとRC4を使用できるため、opensslextraを有効にする際にこれらの機能も有効にすることを推奨します(--enable-des3 --enable-arc4)。wolfSSLは現在RC2をサポートしていないため、RC2での復号は現在利用できません。これは、OpenSSLコマンドラインで.p12ファイルを作成する際に使用されるデフォルトの暗号化スキームで顕著になる可能性があります。wolfSSL_PKCS12_parse(PKCS12_parse)。この関数が最初に行うことは、存在する場合にMACが正しいかどうかを確認することです。MACが失敗した場合、関数は返され、保存されているコンテンツ情報の復号を試みません。この関数は、各コンテンツ情報を解析してバッグタイプを探し、バッグタイプが既知の場合、必要に応じて復号され、構築中の証明書リストまたは見つかった鍵として保存されます。すべてのバッグを解析した後、見つかった鍵は証明書リストと比較され、一致するペアが見つかります。この一致するペアは、鍵と証明書として返されます。オプションで、見つかった証明書リストはSTACK_OFの証明書として返されます。現時点では、CRL、Secret、またはSafeContentsバッグはスキップされ、解析されません。これらまたは他の「不明な」バッグがスキップされているかどうかは、デバッグ出力を表示することで確認できます。フレンドリ名などの追加属性は、PKCS12ファイルを解析する際にスキップされます。

    \return SSL_SUCCESS PKCS12の解析が成功した場合。
    \return SSL_FAILURE エラーケースに遭遇した場合。

    \param pkcs12 解析するWC_PKCS12構造体。
    \param paswd PKCS12を復号するためのパスワード。
    \param pkey PKCS12から復号された秘密鍵を保持する構造体。
    \param cert PKCS12から復号された証明書を保持する構造体。
    \param stack 追加の証明書のオプションスタック。

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bioはPKCS12ファイルを読み込みます。
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, "a password", &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //cert、pkey、およびオプションでcertsスタックを使用します。
    \endcode

    \sa wolfSSL_d2i_PKCS12_bio
    \sa wc_PKCS12_free
*/
int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
     WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert, WOLF_STACK_OF(WOLFSSL_X509)** ca);

/*!
    \ingroup CertsKeys

    \brief サーバDiffie-Hellmanエフェメラルパラメータの設定。この関数は、サーバがDHEを使用する暗号スイートをネゴシエートする場合に使用されるグループパラメータを設定します。

    \return SSL_SUCCESS 成功時。
    \return MEMORY_ERROR メモリエラーが発生した場合に返されます。
    \return SIDE_ERROR この関数がSSLサーバではなくSSLクライアントで呼び出された場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param p Diffie-Hellman素数パラメータ。
    \param pSz pのサイズ。
    \param g Diffie-Hellman「生成元」パラメータ。
    \param gSz gのサイズ。

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

    \brief この関数は、Diffie-HellmanパラメータのラッパーであるwolfSSL_SetTMpDH_buffer_wrapperを呼び出します。

    \return SSL_SUCCESS 実行が成功した場合。
    \return SSL_BAD_FILETYPE ファイルタイプがPEMでなく、ASN.1でもない場合。また、wc_DhParamsLoadが正常に返されなかった場合にも返されます。
    \return SSL_NO_PEM_HEADER PEMヘッダが存在しない場合、PemToDerから返されます。
    \return SSL_BAD_FILE PemToDerでファイルエラーがあった場合に返されます。
    \return SSL_FATAL_ERROR コピーエラーがあった場合、PemToDerから返されます。
    \return MEMORY_E メモリ割り当てエラーがあった場合。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合、またはサブルーチンにNULL引数が渡された場合に返されます。
    \return DH_KEY_SIZE_E wolfSSL_SetTmpDH()またはwolfSSL_CTX_SetTmpDH()でキーサイズエラーがある場合に返されます。
    \return SIDE_ERROR wolfSSL_SetTmpDHでサーバ側でない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf wolfSSL_SetTMpDH_file_wrapperから渡される割り当てられたバッファ。
    \param sz ファイル(wolfSSL_SetTmpDH_file_wrapper内のfname)のサイズを保持するlong int型。
    \param format wolfSSL_SetTmpDH_file_wrapper()から渡される証明書形式の表現である整数型。

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

    \brief この関数は、wolfSSL_SetTmpDH_file_wrapperを呼び出してサーバDiffie-Hellmanパラメータを設定します。

    \return SSL_SUCCESS この関数とそのサブルーチンが正常に完了した場合に返されます。
    \return MEMORY_E この関数またはサブルーチンでメモリ割り当てが失敗した場合に返されます。
    \return SIDE_ERROR WOLFSSL構造体内のOptions構造体のsideメンバがサーバ側でない場合。
    \return SSL_BAD_FILETYPE 証明書が一連のチェックに失敗した場合に返されます。
    \return DH_KEY_SIZE_E DHパラメータの鍵サイズがWOLFSSL構造体のminDhKeySzメンバの値より小さい場合に返されます。
    \return DH_KEY_SIZE_E DHパラメータの鍵サイズがWOLFSSL構造体のmaxDhKeySzメンバの値より大きい場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL構造体など、許可されていない引数値がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param fname 証明書を保持する定数char型ポインタ。
    \param format 証明書の形式を保持する整数型。

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

    \brief サーバCTX Diffie-Hellmanのパラメータを設定します。

    \return SSL_SUCCESS 関数とすべてのサブルーチンがエラーなく返された場合に返されます。
    \return BAD_FUNC_ARG CTX、pまたはgパラメータがNULLの場合に返されます。
    \return DH_KEY_SIZE_E DHパラメータの鍵サイズがWOLFSSL_CTX構造体のminDhKeySzメンバの値より小さい場合に返されます。
    \return DH_KEY_SIZE_E DHパラメータの鍵サイズがWOLFSSL_CTX構造体のmaxDhKeySzメンバの値より大きい場合に返されます。
    \return MEMORY_E この関数またはサブルーチンでメモリ割り当てが失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param p serverDH_P構造体のbufferメンバに読み込まれる定数unsigned char型ポインタ。
    \param pSz pのサイズを表すint型で、MAX_DH_SIZEに初期化されます。
    \param g serverDH_G構造体のbufferメンバに読み込まれる定数unsigned char型ポインタ。
    \param gSz gのサイズを表すint型で、MAX_DH_SIZEに初期化されます。

    _Exmaple_
    \code
    WOLFSSL_CTX* ctx =  WOLFSSL_CTX_new( protocol );
    byte* p;
    byte* g;
    word32 pSz = (word32)sizeof(p)/sizeof(byte);
    word32 gSz = (word32)sizeof(g)/sizeof(byte);
    …
    int ret =  wolfSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);

    if(ret != SSL_SUCCESS){
    	// 失敗ケース
    }
    \endcode

    \sa wolfSSL_SetTmpDH
    \sa wc_DhParamsLoad
*/
int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);

/*!
    \ingroup CertsKeys

    \brief wolfSSL_SetTmpDH_buffer_wrapperを呼び出すラッパー関数です。

    \return 0 実行が成功した場合に返されます。
    \return BAD_FUNC_ARG ctxまたはbufパラメータがNULLの場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合。
    \return SSL_BAD_FILETYPE formatが正しくない場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf バッファとして割り当てられ、wolfSSL_SetTmpDH_buffer_wrapperに渡される定数unsigned char型へのポインタ。
    \param sz wolfSSL_SetTmpDH_file_wrapper()のfnameパラメータから導出されるlong整数型。
    \param format wolfSSL_SetTmpDH_file_wrapper()から渡される整数型。

    _Example_
    \code
    static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
        Const char* fname, int format);
    #ifdef WOLFSSL_SMALL_STACK
    byte staticBuffer[1]; // ヒープ使用を強制
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

    \brief この関数は、wolfSSL_SetTmpDH_file_wrapperを呼び出してサーバDiffie-Hellmanパラメータを設定します。

    \return SSL_SUCCESS wolfSSL_SetTmpDH_file_wrapperまたはそのサブルーチンのいずれかが正常に返された場合に返されます。
    \return MEMORY_E サブルーチンで動的メモリの割り当てが失敗した場合に返されます。
    \return BAD_FUNC_ARG ctxまたはfnameパラメータがNULLの場合、またはサブルーチンにNULL引数が渡された場合に返されます。
    \return SSL_BAD_FILE 証明書ファイルを開けない場合、またはwolfSSL_SetTmpDH_file_wrapperからのファイルに対する一連のチェックが失敗した場合に返されます。
    \return SSL_BAD_FILETYPE wolfSSL_SetTmpDH_buffer_wrapper()から、形式がPEMでもASN.1でもない場合に返されます。
    \return DH_KEY_SIZE_E DHパラメータの鍵サイズがWOLFSSL_CTX構造体のminDhKeySzメンバの値より小さい場合に返されます。
    \return DH_KEY_SIZE_E DHパラメータの鍵サイズがWOLFSSL_CTX構造体のmaxDhKeySzメンバの値より大きい場合に返されます。
    \return SIDE_ERROR サーバ側でない場合、wolfSSL_SetTmpDH()で返されます。
    \return SSL_NO_PEM_HEADER PEMヘッダがない場合、PemToDerから返されます。
    \return SSL_FATAL_ERROR メモリコピーの失敗がある場合、PemToDerから返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param fname 証明書ファイルへの定数文字ポインタ。
    \param format 証明書形式の表現である、wolfSSL_SetTmpDH_file_wrapper()から渡される整数型。

    _Example_
    \code
    #define dhParam     "certs/dh2048.pem"
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
    \sa wolfSSL_CTX_SetTmpDH_buffer    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa AllocDer
    \sa PemToDer
*/
int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* f,
                                             int format);

/*!
    \ingroup CertsKeys

    \brief この関数は、WOLFSSL_CTX構造体のminDhKeySzメンバにアクセスして、Diffie-Hellman鍵サイズの最小サイズ(ビット単位)を設定します。

    \return SSL_SUCCESS 関数が正常に完了した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、またはkeySz_bitsが16,000より大きいか8で割り切れない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param keySz_bits 最小DH鍵サイズをビット単位で設定するために使用されるword16型。WOLFSSL_CTX構造体はこの情報をminDhKeySzメンバに保持します。

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

    \brief WOLFSSL構造体内のDiffie-Hellman鍵の最小サイズ(ビット単位)を設定します。

    \return SSL_SUCCESS 最小サイズが正常に設定されました。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合、またはkeySz_bitsが16,000より大きいか8で割り切れない場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param keySz_bits 最小DH鍵サイズをビット単位で設定するために使用されるword16型。WOLFSSL_CTX構造体はこの情報をminDhKeySzメンバに保持します。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz_bits;
    ...
    if(wolfSSL_SetMinDhKey_Sz(ssl, keySz_bits) != SSL_SUCCESS){
	    // 設定に失敗しました
    }
    \endcode

    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief この関数は、WOLFSSL_CTX構造体のmaxDhKeySzメンバにアクセスして、Diffie-Hellman鍵サイズの最大サイズ(ビット単位)を設定します。

    \return SSL_SUCCESS 関数が正常に完了した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、またはkeySz_bitsが16,000より大きいか8で割り切れない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param keySz_bits 最大DH鍵サイズをビット単位で設定するために使用されるword16型。WOLFSSL_CTX構造体はこの情報をmaxDhKeySzメンバに保持します。

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

    \brief WOLFSSL構造体内のDiffie-Hellman鍵の最大サイズ(ビット単位)を設定します。

    \return SSL_SUCCESS 最大サイズが正常に設定されました。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合、またはkeySzパラメータが許容サイズより大きいか8で割り切れない場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param keySz 最大DH鍵のビットサイズを表すword16型。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz;
    ...
    if(wolfSSL_SetMaxDhKey(ssl, keySz) != SSL_SUCCESS){
	    // 設定に失敗しました
    }
    \endcode

    \sa wolfSSL_CTX_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMaxDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief options構造体のメンバであるdhKeySzの値(ビット単位)を返します。この値は、Diffie-Hellman鍵サイズをバイト単位で表します。

    \return dhKeySz ssl->options.dhKeySzに保持されている値を返します。これはビット単位のサイズを表す整数値です。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int dhKeySz;
    ...
    dhKeySz = wolfSSL_GetDhKey_Sz(ssl);

    if(dhKeySz == BAD_FUNC_ARG || dhKeySz <= 0){
    	// 失敗ケース
    } else {
    	// dhKeySzは鍵のサイズを保持しています
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

    \brief WOLFSSL_CTX構造体とWOLFSSL_CERT_MANAGER構造体の両方で最小RSA鍵サイズを設定します。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。
    \return BAD_FUNC_ARG ctx構造体がNULLの場合、またはkeySzがゼロ未満か8で割り切れない場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param keySz ctx構造体とcm構造体のminRsaKeySzに格納され、バイトに変換されるshort整数型。

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

    \brief WOLFSSL構造体にあるRSAの最小許容鍵サイズをビット単位で設定します。

    \return SSL_SUCCESS 最小値が正常に設定されました。
    \return BAD_FUNC_ARG ssl構造体がNULLの場合、またはksySzがゼロ未満か8で割り切れない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param keySz 最小鍵をビット単位で表すshort整数値。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    short keySz;
    …

    int isSet =  wolfSSL_SetMinRsaKey_Sz(ssl, keySz);
    if(isSet != SSL_SUCCESS){
	    設定に失敗しました
    }
    \endcode

    \sa wolfSSL_CTX_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinRsaKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief WOLF_CTX構造体とWOLFSSL_CERT_MANAGER構造体でECC鍵の最小サイズをビット単位で設定します。

    \return SSL_SUCCESS 実行が成功し、minEccKeySzメンバが設定された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、またはkeySzが負の値か8で割り切れない場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param keySz 最小ECC鍵サイズをビット単位で表すshort整数型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    short keySz; // 最小鍵サイズ
    …
    if(wolfSSL_CTX_SetMinEccKey(ctx, keySz) != SSL_SUCCESS){
	    // 最小鍵サイズの設定に失敗しました
    }
    \endcode

    \sa wolfSSL_SetMinEccKey_Sz
*/
int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief options構造体のminEccKeySzメンバの値を設定します。options構造体はWOLFSSL構造体のメンバであり、sslパラメータを通じてアクセスされます。

    \return SSL_SUCCESS 関数がoptions構造体のminEccKeySzメンバを正常に設定した場合。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、または鍵サイズ(keySz)が0未満か8で割り切れない場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param keySz 最小ECC鍵サイズを設定するために使用される値。options構造体に値を設定します。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx); // 新しいセッション
    short keySz = 999; // 許容される最小鍵サイズに設定すべきです
    ...
    if(wolfSSL_SetMinEccKey_Sz(ssl, keySz) != SSL_SUCCESS){
	    // 失敗ケース
    }
    \endcode

    \sa wolfSSL_CTX_SetMinEccKey_Sz
    \sa wolfSSL_CTX_SetMinRsaKey_Sz
    \sa wolfSSL_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinEccKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief この関数は、マスターシークレットから鍵材料を導出するためにEAP_TLSとEAP-TTLSによって使用されます。

    \return BUFFER_E バッファの実際のサイズが許容される最大サイズを超えた場合に返されます。
    \return MEMORY_E メモリ割り当てでエラーが発生した場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param key p_hash関数の結果を保持するvoidポインタ変数。
    \param len key変数の長さを表すunsigned整数。
    \param label wc_PRF()でコピーされる定数charポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);;
    void* key;
    unsigned int len;
    const char* label;
    …
    return wolfSSL_make_eap_keys(ssl, key, len, label);
    \endcode

    \sa wc_PRF
    \sa wc_HmacFinal
    \sa wc_HmacUpdate
*/
int wolfSSL_make_eap_keys(WOLFSSL* ssl, void* key, unsigned int len,
                                                             const char* label);

/*!
    \ingroup IO

    \brief writevのセマンティクスをシミュレートしますが、SSL_write()の動作とフロント追加が小さい場合があるため、実際には一度にブロック単位では行いません。writevを使用するソフトウェアへの移植を容易にします。

    \return ＞0 成功時、書き込まれたバイト数。
    \return 0 失敗時に返されます。wolfSSL_get_error()を呼び出して特定のエラーコードを取得してください。
    \return MEMORY_ERROR メモリエラーが発生した場合に返されます。
    \return SSL_FATAL_ERROR エラーが発生した場合、またはノンブロッキングソケットを使用しているときにSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEエラーを受信し、アプリケーションがwolfSSL_write()を再度呼び出す必要がある場合に返されます。wolfSSL_get_error()を使用して特定のエラーコードを取得してください。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param iov 書き込むI/Oベクトルの配列。
    \param iovcnt iov配列内のベクトル数。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char *bufA = "hello\n";
    char *bufB = "hello world\n";
    int iovcnt;
    struct iovec iov[2];

    iov[0].iov_base = buffA;
    iov[0].iov_len = strlen(buffA);
    iov[1].iov_base = buffB;
    iov[1].iov_len = strlen(buffB);
    iovcnt = 2;
    ...
    ret = wolfSSL_writev(ssl, iov, iovcnt);
    // "ret"バイトを書き込みました。または<=0の場合はエラー
    \endcode

    \sa wolfSSL_write
*/
int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);

/*!
    \ingroup Setup

    \brief この関数は、CA署名者リストをアンロードし、署名者テーブル全体を解放します。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、またはサブルーチンで許可されない引数値が渡された場合に返されます。
    \return BAD_MUTEX_E mutexエラーが発生した場合に返されます。LockMutex()が0を返しませんでした。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    if(wolfSSL_CTX_UnloadCAs(ctx) != SSL_SUCCESS){
    	// 関数はCAをアンロードしませんでした
    }
    \endcode

    \sa wolfSSL_CertManagerUnloadCAs
    \sa LockMutex
    \sa UnlockMutex
*/
int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX*);


/*!
    \ingroup Setup

    \brief この関数は、CA署名者リストに追加された中間証明書をアンロードし、解放します。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、またはサブルーチンで許可されない引数値が渡された場合に返されます。
    \return BAD_STATE_E WOLFSSL_CTXの参照カウントが1より大きい場合に返されます。    \return BAD_MUTEX_E mutexエラーが発生した場合に返されます。LockMutex()が0を返しませんでした。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    if(wolfSSL_CTX_UnloadIntermediateCerts(ctx) != NULL){
        // 関数はCAをアンロードしませんでした
    }
    \endcode

    \sa wolfSSL_CTX_UnloadCAs
    \sa wolfSSL_CertManagerUnloadIntermediateCerts
*/
int wolfSSL_CTX_UnloadIntermediateCerts(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief この関数は以前にロードされたすべての信頼されたピア証明書をアンロードするために使用されます。この機能は、マクロWOLFSSL_TRUST_PEER_CERTを定義することで有効になります。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG ctxがNULLの場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_Unload_trust_peers(ctx);
    if (ret != SSL_SUCCESS) {
        // 信頼されたピア証明書のアンロードエラー
    }
    ...
    \endcode

    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_trust_peer_cert
*/
int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief この関数は、TLS/SSLハンドシェイクを実行する際にピアを検証するために使用する証明書をロードします。ハンドシェイク中に送信されるピア証明書は、利用可能な場合はSKIDと署名を使用して比較されます。これら2つが一致しない場合は、ロードされたCAが使用されます。ファイルではなくバッファからの入力である点を除いて、wolfSSL_CTX_trust_peer_certと同じ機能です。この機能は、マクロWOLFSSL_TRUST_PEER_CERTを定義することで有効になります。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE ctxがNULL、またはfileとtypeの両方が無効な場合に返されます。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param buffer 証明書を含むバッファへのポインタ。
    \param sz 入力バッファの長さ。
    \param type ロードされる証明書のタイプ、すなわちSSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...

    ret = wolfSSL_CTX_trust_peer_buffer(ctx, bufferPtr, bufferSz,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        // 信頼されたピア証明書のロードエラー
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

    \brief この関数はCA証明書バッファをWOLFSSLコンテキストにロードします。バッファ非対応版と同様に動作しますが、ファイルの代わりにバッファを入力として呼び出せる点が異なります。バッファはサイズszのin引数によって提供されます。formatはバッファの形式タイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。形式がPEMであれば、1つのバッファに複数のCA証明書をロードできます。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return BUFFER_E チェーンバッファが受信バッファより大きい場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in CA証明書バッファへのポインタ。
    \param sz 入力CA証明書バッファ(in)のサイズ。
    \param format バッファ証明書の形式、SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    ret = wolfSSL_CTX_load_verify_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// バッファからのCA証明書のロードエラー
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

    \brief この関数はCA証明書バッファをWOLFSSLコンテキストにロードします。バッファ非対応版と同様に動作しますが、ファイルの代わりにバッファを入力として呼び出せる点が異なります。バッファはサイズszのin引数によって提供されます。formatはバッファの形式タイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。形式がPEMであれば、1つのバッファに複数のCA証明書をロードできます。_ex版はPR 2413で追加され、userChainとflagsの追加引数をサポートします。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return BUFFER_E チェーンバッファが受信バッファより大きい場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in CA証明書バッファへのポインタ。
    \param sz 入力CA証明書バッファ(in)のサイズ。
    \param format バッファ証明書の形式、SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。
    \param userChain 形式WOLFSSL_FILETYPE_ASN1を使用している場合、これを非ゼロに設定すると、DERのチェーンが提示されていることを示します。
    \param flags ssl.hのWOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS付近を参照してください。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    // 期限切れ証明書を強制的にロードする例
    ret = wolfSSL_CTX_load_verify_buffer_ex(ctx, certBuff, sz, SSL_FILETYPE_PEM,
        0, (WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY));
    if (ret != SSL_SUCCESS) {
    	// バッファからのCA証明書のロードエラー
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

    \brief この関数はCA証明書チェーンバッファをWOLFSSLコンテキストにロードします。バッファ非対応版と同様に動作しますが、ファイルの代わりにバッファを入力として呼び出せる点が異なります。バッファはサイズszのin引数によって提供されます。formatはバッファの形式タイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。形式がPEMであれば、1つのバッファに複数のCA証明書をロードできます。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return BUFFER_E チェーンバッファが受信バッファより大きい場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in CA証明書バッファへのポインタ。
    \param sz 入力CA証明書バッファ(in)のサイズ。
    \param format バッファ証明書の形式、SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    ret = wolfSSL_CTX_load_verify_chain_buffer_format(ctx,
                         certBuff, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        // バッファからのCA証明書のロードエラー
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

    \brief この関数は証明書バッファをWOLFSSLコンテキストにロードします。バッファ非対応版と同様に動作しますが、ファイルの代わりにバッファを入力として呼び出せる点が異なります。バッファはサイズszのin引数によって提供されます。formatはバッファの形式タイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in ロードする証明書を含む入力バッファ。
    \param sz 入力バッファのサイズ。
    \param format 入力バッファ(in)に格納されている証明書の形式。指定可能な値はSSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // バッファからの証明書のロードエラー
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

    \brief この関数は秘密鍵バッファをSSLコンテキストにロードします。バッファ非対応版と同様に動作しますが、ファイルの代わりにバッファを入力として呼び出せる点が異なります。バッファはサイズszのin引数によって提供されます。formatはバッファの形式タイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return NO_PASSWORD 鍵ファイルが暗号化されているがパスワードが提供されていない場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in ロードする秘密鍵を含む入力バッファ。
    \param sz 入力バッファのサイズ。
    \param format 入力バッファ(in)に格納されている秘密鍵の形式。指定可能な値はSSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte keyBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, keyBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// バッファからの秘密鍵のロードエラー
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

    \brief この関数は証明書チェーンバッファをWOLFSSLコンテキストにロードします。バッファ非対応版と同様に動作しますが、ファイルの代わりにバッファを入力として呼び出せる点が異なります。バッファはサイズszのin引数によって提供されます。バッファはPEM形式で、サブジェクトの証明書から始まり、ルート証明書で終わる必要があります。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return BUFFER_E チェーンバッファが受信バッファより大きい場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param in ロードするPEM形式の証明書チェーンを含む入力バッファ。
    \param sz 入力バッファのサイズ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certChainBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx, certChainBuff, sz);
    if (ret != SSL_SUCCESS) {
    	// バッファから証明書チェーンの読み込みに失敗
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

    \brief この関数は、証明書バッファをWOLFSSLオブジェクトにロードします。バッファなしバージョンと同様に動作しますが、ファイルの代わりにバッファを入力として呼び出すことができる点が異なります。バッファはサイズszのin引数によって提供されます。formatはバッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルのフォーマットが間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードに失敗した場合に返されます。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param in ロードする証明書を含むバッファ。
    \param sz バッファ内の証明書のサイズ。
    \param format ロードする証明書のフォーマット。指定可能な値はSSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。

    _Example_
    \code
    int ret;
    byte certBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...

    ret = wolfSSL_use_certificate_buffer(ssl, certBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// バッファから証明書の読み込みに失敗
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

    \brief この関数は、秘密鍵バッファをWOLFSSLオブジェクトにロードします。バッファなしバージョンと同様に動作しますが、ファイルの代わりにバッファを入力として呼び出すことができる点が異なります。バッファはサイズszのin引数によって提供されます。formatはバッファのフォーマットタイプを指定します。SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。適切な使用方法については例を参照してください。

    \return SSL_SUCCESS 成功時。
    \return SSL_BAD_FILETYPE ファイルのフォーマットが間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードに失敗した場合に返されます。
    \return NO_PASSWORD 鍵ファイルが暗号化されているがパスワードが提供されていない場合に返されます。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param in ロードする秘密鍵を含むバッファ。
    \param sz バッファ内の秘密鍵のサイズ。
    \param format ロードする秘密鍵のフォーマット。指定可能な値はSSL_FILETYPE_ASN1またはSSL_FILETYPE_PEMです。

    _Example_
    \code
    int ret;
    byte keyBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...
    ret = wolfSSL_use_PrivateKey_buffer(ssl, keyBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// バッファから秘密鍵の読み込みに失敗
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

    \brief この関数は、証明書チェーンバッファをWOLFSSLオブジェクトにロードします。バッファなしバージョンと同様に動作しますが、ファイルの代わりにバッファを入力として呼び出すことができる点が異なります。バッファはサイズszのin引数によって提供されます。バッファはPEMフォーマットである必要があり、サブジェクトの証明書から始まり、ルート証明書で終わる必要があります。適切な使用方法については例を参照してください。

    \return SSL_SUCCES 成功時。
    \return SSL_BAD_FILETYPE ファイルのフォーマットが間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードに失敗した場合に返されます。
    \return BUFFER_E チェーンバッファが受信バッファより大きい場合に返されます。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param in ロードする証明書を含むバッファ。
    \param sz バッファ内の証明書のサイズ。

    _Example_
    \code
    int ret;
    byte certChainBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...
    ret = wolfSSL_use_certificate_chain_buffer(ssl, certChainBuff, buffSz);
    if (ret != SSL_SUCCESS) {
    	// バッファから証明書チェーンの読み込みに失敗
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

    \brief この関数は、SSLが所有する証明書または鍵をアンロードします。

    \return SSL_SUCCESS 関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSLオブジェクトがNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    int unloadKeys = wolfSSL_UnloadCertsKeys(ssl);
    if(unloadKeys != SSL_SUCCESS){
	    // 失敗ケース
    }
    \endcode

    \sa wolfSSL_CTX_UnloadCAs
*/
int wolfSSL_UnloadCertsKeys(WOLFSSL*);

/*!
    \ingroup Setup

    \brief この関数は、可能な場合にハンドシェイクメッセージのグループ化をオンにします。

    \return SSL_SUCCESS 成功時に返されます。
    \return BAD_FUNC_ARG 入力コンテキストがnullの場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_group_messages(ctx);
    if (ret != SSL_SUCCESS) {
	    // ハンドシェイクメッセージのグループ化の設定に失敗
    }
    \endcode

    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_new
*/
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief この関数は、可能な場合にハンドシェイクメッセージのグループ化をオンにします。

    \return SSL_SUCCESS 成功時に返されます。
    \return BAD_FUNC_ARG 入力コンテキストがnullの場合に返されます。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_group_messages(ssl);
    if (ret != SSL_SUCCESS) {
	    // ハンドシェイクメッセージのグループ化の設定に失敗
    }
    \endcode

    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_new
*/
int wolfSSL_set_group_messages(WOLFSSL*);

/*!
    \brief この関数はファザーコールバックを設定します。

    \return none 戻り値はありません。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cbf 次の形式の関数ポインタであるCallbackFuzzer型: int (*CallbackFuzzer)(WOLFSSL* ssl, const unsigned char* buf, int sz, int type, void* fuzzCtx);
    \param fCtx WOLFSSL構造体のfuzzerCtxメンバに設定されるvoidポインタ型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* fCtx;

    int callbackFuzzerCB(WOLFSSL* ssl, const unsigned char* buf, int sz,
				int type, void* fuzzCtx){
        // 関数定義
    }
    …
    wolfSSL_SetFuzzerCb(ssl, callbackFuzzerCB, fCtx);
    \endcode

    \sa CallbackFuzzer
*/
void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx);

/*!
    \brief この関数は新しいdtls cookieシークレットを設定します。

    \return 0 関数がエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG 関数に許容できない値を持つ引数が渡された場合に返されます。
    \return COOKIE_SECRET_SZ シークレットサイズが0の場合に返されます。
    \return MEMORY_ERROR 新しいcookieシークレット用のメモリ割り当てに問題があった場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param secret シークレットバッファを表す定数バイトポインタ。
    \param secretSz バッファのサイズ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const* byte secret;
    word32 secretSz; // secretのサイズ
    …
    if(!wolfSSL_DTLS_SetCookieSecret(ssl, secret, secretSz)){
    	// DTLSクッキーシークレットの設定失敗のコードブロック
    } else {
    	// 成功！クッキーシークレットが設定されました
    }
    \endcode

    \sa ForceZero
    \sa wc_RNG_GenerateBlock
*/
int   wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl,
                                               const unsigned char* secret,
                                               unsigned int secretSz);

/*!
    \brief この関数は乱数を取得します。

    \return rng 成功時。
    \return NULL sslがNULLの場合。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。

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

    \brief この関数は、許可される最小ダウングレードバージョンを設定します。ダウングレードを許可する接続(wolfSSLv23_client_methodまたはwolfSSLv23_server_method)を使用する場合にのみ適用されます。

    \return SSL_SUCCESS 関数がエラーなく戻り、最小バージョンが設定された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、または最小バージョンがサポートされていない場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param version 最小値として設定されるバージョンの整数表現: WOLFSSL_SSLV3 = 0、WOLFSSL_TLSV1 = 1、WOLFSSL_TLSV1_1 = 2、またはWOLFSSL_TLSV1_2 = 3。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version; // マクロ表現
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
    	// 最小バージョンの設定に失敗
    }
    \endcode

    \sa SetMinVersionHelper
*/
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup TLS

    \brief この関数は、許可される最小ダウングレードバージョンを設定します。ダウングレードを許可する接続(wolfSSLv23_client_methodまたはwolfSSLv23_server_method)を使用する場合にのみ適用されます。

    \return SSL_SUCCESS この関数とそのサブルーチンがエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG SSLオブジェクトがNULLの場合に返されます。サブルーチンでは、バージョンマッチが良好でない場合にこのエラーがスローされます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param version 最小値として設定されるバージョンの整数表現: WOLFSSL_SSLV3 = 0、WOLFSSL_TLSV1 = 1、WOLFSSL_TLSV1_1 = 2、またはWOLFSSL_TLSV1_2 = 3。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol method);
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version;  // マクロ表現
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
	    // 最小バージョンの設定に失敗
    }
    \endcode

    \sa SetMinVersionHelper
*/
int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version);

/*!
    \brief この関数はWOLFSSLオブジェクトのサイズを返し、ビルドオプションと設定に依存します。wolfSSLをビルドする際にSHOW_SIZESが定義されている場合、この関数はWOLFSSLオブジェクト内の個々のオブジェクト(Suites、Ciphersなど)のサイズもstdoutに出力します。

    \return size この関数はWOLFSSLオブジェクトのサイズを返します。

    \param none パラメータはありません。

    _Example_
    \code
    int size = 0;
    size = wolfSSL_GetObjectSize();
    printf("sizeof(WOLFSSL) = %d\n", size);
    \endcode

    \sa wolfSSL_new
*/
int wolfSSL_GetObjectSize(void);  /* ビルドに基づくオブジェクトサイズ */
/*!
    \brief 平文入力のレコード層サイズを返します。これは、アプリケーションが指定された平文入力サイズに対して、トランスポート層を介して送信されるバイト数を知りたい場合に役立ちます。この関数は、SSL/TLSハンドシェイクが完了した後に呼び出す必要があります。

    \return size 成功時には、要求されたサイズが返されます。
    \return INPUT_SIZE_E 入力サイズが最大TLSフラグメントサイズより大きい場合に返されます(wolfSSL_GetMaxOutputSize()を参照)。
    \return BAD_FUNC_ARG 無効な関数引数が渡された場合、またはSSL/TLSハンドシェイクがまだ完了していない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。
    \param inSz 平文データのサイズ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetMaxOutputSize
*/
int wolfSSL_GetOutputSize(WOLFSSL* ssl, int inSz);

/*!
    \brief 平文データの最大レコード層サイズを返します。これは、プロトコル標準で指定されている最大SSL/TLSレコードサイズ、またはTLS最大フラグメント長拡張によって設定された最大TLSフラグメントサイズのいずれかに対応します。この関数は、アプリケーションがwolfSSL_GetOutputSize()を呼び出してINPUT_SIZE_Eエラーを受け取った場合に役立ちます。この関数は、SSL/TLSハンドシェイクが完了した後に呼び出す必要があります。

    \return size 成功時には、最大出力サイズが返されます。
    \return BAD_FUNC_ARG 無効な関数引数が渡された場合、またはSSL/TLSハンドシェイクがまだ完了していない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetOutputSize
*/
int wolfSSL_GetMaxOutputSize(WOLFSSL*);

/*!
    \ingroup Setup

    \brief この関数は、versionで指定されたバージョンを使用して、指定されたSSLセッション(WOLFSSLオブジェクト)のSSL/TLSプロトコルバージョンを設定します。これにより、SSLセッション(ssl)のプロトコル設定が上書きされます。これは元々SSLコンテキスト(wolfSSL_CTX_new())のメソッドタイプによって定義および設定されたものです。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 入力されたSSLオブジェクトがNULLの場合、またはversionに不正なプロトコルバージョンが指定された場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param version SSL/TLSプロトコルバージョン。指定可能な値には、WOLFSSL_SSLV3、WOLFSSL_TLSV1、WOLFSSL_TLSV1_1、WOLFSSL_TLSV1_2があります。

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_SetVersion(ssl, WOLFSSL_TLSV1);
    if (ret != SSL_SUCCESS) {
        // SSLセッションのプロトコルバージョンの設定に失敗しました。
    }
    \endcode

    \sa wolfSSL_CTX_new
*/
int wolfSSL_SetVersion(WOLFSSL* ssl, int version);

/*!
    \brief 呼び出し元がアトミックユーザレコード処理Mac/暗号化コールバックを設定できるようにします。コールバックは、成功時には0、エラー時には<0を返す必要があります。sslとctxポインタは、ユーザの利便性のために利用可能です。macOutは、macの結果を格納する出力バッファです。macInはmac入力バッファであり、macInSzはバッファのサイズを示します。macContentとmacVerifyは、wolfSSL_SetTlsHmacInner()に必要であり、そのまま渡す必要があります。encOutは、暗号化の結果を格納する出力バッファです。encInは暗号化する入力バッファであり、encSzは入力のサイズです。コールバックの例は、wolfssl/test.hのmyMacEncryptCb()にあります。

    \return none 戻り値なし。

    \param No パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX* ctx, CallbackMacEncrypti cb);

/*!
    \brief 呼び出し元がアトミックユーザレコード処理Mac/暗号化コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元が、wolfSSL_SetMacEncryptCtx()で以前に保存されたアトミックユーザレコード処理Mac/暗号化コールバックコンテキストを取得できるようにします。

    \return pointer 成功した場合、呼び出しはコンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストの場合に返されます。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_SetMacEncryptCtx
*/
void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

/*!
    \brief 呼び出し元がアトミックユーザレコード処理復号/検証コールバックを設定できるようにします。コールバックは、成功時には0、エラー時には<0を返す必要があります。sslとctxポインタは、ユーザの利便性のために利用可能です。decOutは、復号の結果を格納する出力バッファです。decInは暗号化された入力バッファであり、decInSzはバッファのサイズを示します。contentとverifyは、wolfSSL_SetTlsHmacInner()に必要であり、そのまま渡す必要があります。padSzは、パディングの合計値を設定する必要がある出力変数です。つまり、macサイズに加えて、パディングとパディングバイトです。コールバックの例は、wolfssl/test.hのmyDecryptVerifyCb()にあります。

    \return none 戻り値なし。

    \param none パラメータなし。

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
    \brief 呼び出し元がアトミックユーザレコード処理復号/検証コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_GetDecryptVerifyCtx
*/
void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元が、wolfSSL_SetDecryptVerifyCtx()で以前に保存されたアトミックユーザレコード処理復号/検証コールバックコンテキストを取得できるようにします。

    \return pointer 成功した場合、呼び出しはコンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストの場合に返されます。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_SetDecryptVerifyCtx
*/
void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

/*!
    \brief ハンドシェイクプロセスからHmac/Macシークレットの取得を可能にします。verifyパラメータは、これがピアメッセージの検証用であるかどうかを指定します。

    \return pointer 成功した場合、呼び出しはシークレットへの有効なポインタを返します。シークレットのサイズは、wolfSSL_GetHmacSize()から取得できます。
    \return NULL エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。
    \param verify これがピアメッセージの検証用であるかどうかを指定します。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetHmacSize
*/
const unsigned char* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify);

/*!
    \brief ハンドシェイクプロセスからクライアント書き込み鍵の取得を可能にします。

    \return pointer 成功した場合、呼び出しは鍵への有効なポインタを返します。鍵のサイズは、wolfSSL_GetKeySize()から取得できます。
    \return NULL エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
*/
const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL*);

/*!
    \brief ハンドシェイクプロセスからクライアント書き込みIV(初期化ベクトル)の取得を可能にします。

    \return pointer 成功した場合、呼び出しはIVへの有効なポインタを返します。IVのサイズは、wolfSSL_GetCipherBlockSize()から取得できます。
    \return NULL エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetCipherBlockSize()
    \sa wolfSSL_GetClientWriteKey()
*/
const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL*);

/*!
    \brief ハンドシェイクプロセスからサーバ書き込み鍵の取得を可能にします。

    \return pointer 成功した場合、呼び出しは鍵への有効なポインタを返します。鍵のサイズは、wolfSSL_GetKeySize()から取得できます。
    \return NULL エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetServerWriteIV
*/
const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL*);

/*!
    \brief ハンドシェイクプロセスからサーバ書き込みIV(初期化ベクトル)の取得を可能にします。

    \return pointer 成功した場合、呼び出しはIVへの有効なポインタを返します。IVのサイズは、wolfSSL_GetCipherBlockSize()から取得できます。
    \return NULL エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetClientWriteKey
*/
const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL*);

/*!
    \brief ハンドシェイクプロセスから鍵サイズの取得を可能にします。

    \return size 成功した場合、呼び出しは鍵サイズをバイト単位で返します。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

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

    \brief WOLFSSL構造体に保持されているspecs構造体のiv_sizeメンバを返します。

    \return iv_size ssl->specs.iv_sizeに保持されている値を返します。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ivSize;
    ...
    ivSize = wolfSSL_GetIVSize(ssl);

    if(ivSize > 0){
    	// ivSizeはspecs.iv_size値を保持しています。
    }
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
    \sa wolfSSL_GetServerWriteIV
*/
int                  wolfSSL_GetIVSize(WOLFSSL*);

/*!
    \brief このWOLFSSL接続のサイド(側)の取得を可能にします。

    \return success 成功した場合、呼び出しはWOLFSSLオブジェクトのサイドに応じて、WOLFSSL_SERVER_ENDまたはWOLFSSL_CLIENT_ENDのいずれかを返します。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
int                  wolfSSL_GetSide(WOLFSSL*);

/*!
    \brief 呼び出し元が、ネゴシエートされたプロトコルバージョンが少なくともTLSバージョン1.1以上であるかどうかを判断できるようにします。

    \return true/false 成功した場合、呼び出しは真の場合は1、偽の場合は0を返します。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetSide
*/
int                  wolfSSL_IsTLSv1_1(WOLFSSL*);/*!
    \brief 呼び出し元がハンドシェイクからネゴシエートされたバルク暗号アルゴリズムを判定できるようにします。

    \return 成功時、以下のいずれかを返します。
    wolfssl_cipher_null、wolfssl_des、wolfssl_triple_des、wolfssl_aes、
    wolfssl_aes_gcm、wolfssl_aes_ccm、wolfssl_camellia。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetBulkCipher(WOLFSSL*);

/*!
    \brief 呼び出し元がハンドシェイクからネゴシエートされた暗号ブロックサイズを判定できるようにします。

    \return size 成功時、暗号ブロックサイズのバイト数を返します。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetCipherBlockSize(WOLFSSL*);

/*!
    \brief 呼び出し元がハンドシェイクからネゴシエートされたaead macサイズを判定できるようにします。暗号タイプWOLFSSL_AEAD_TYPE用。

    \return size 成功時、aead macサイズのバイト数を返します。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetAeadMacSize(WOLFSSL*);

/*!
    \brief 呼び出し元がハンドシェイクからネゴシエートされた(h)macサイズを判定できるようにします。WOLFSSL_AEAD_TYPE以外の暗号タイプ用。

    \return size 成功時、(h)macサイズのバイト数を返します。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetHmacSize(WOLFSSL*);

/*!
    \brief 呼び出し元がハンドシェイクからネゴシエートされた(h)macタイプを判定できるようにします。WOLFSSL_AEAD_TYPE以外の暗号タイプ用。

    \return 成功時、以下のいずれかを返します。
    MD5、SHA、SHA256、SHA384。
    \return BAD_FUNC_ARG エラー状態の場合に返される可能性があります。
    \return SSL_FATAL_ERROR エラー状態の場合に返される可能性があります。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacSize
*/
int                  wolfSSL_GetHmacType(WOLFSSL*);

/*!
    \brief 呼び出し元がハンドシェイクからネゴシエートされた暗号タイプを判定できるようにします。

    \return 成功時、以下のいずれかを返します。
    WOLFSSL_BLOCK_TYPE、WOLFSSL_STREAM_TYPE、WOLFSSL_AEAD_TYPE。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetCipherType(WOLFSSL*);

/*!
    \brief 呼び出し元がメッセージの送受信のためにHmac Innerベクトルを設定できるようにします。結果はinnerに書き込まれ、少なくともwolfSSL_GetHmacSize()バイトである必要があります。メッセージのサイズはszで指定され、contentはメッセージのタイプ、verifyはこれがピアメッセージの検証であるかを指定します。WOLFSSL_AEAD_TYPEを除く暗号タイプで有効です。

    \return 1 成功時。
    \return BAD_FUNC_ARG エラー状態の場合に返されます。

    \param none パラメータなし。

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
    \brief 呼び出し元がECC署名用の公開鍵コールバックを設定できるようにします。コールバックは成功時に0、エラー時に0未満を返す必要があります。sslとctxポインタはユーザの便宜のために利用可能です。inは署名する入力バッファで、inSzは入力の長さを示します。outは署名の結果を格納する出力バッファです。outSzは入出力変数で、呼び出し時の出力バッファのサイズを指定し、返す前に署名の実際のサイズをそこに格納する必要があります。keyDerはASN1形式のECC秘密鍵で、keySzは鍵の長さをバイト単位で表します。コールバックの例はwolfssl/test.h myEccSign()にあります。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetEccSignCtx
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx, CallbackEccSign cb);

/*!
    \brief 呼び出し元が公開鍵ECC署名コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。
    \param ctx 格納するユーザコンテキストへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元が以前にwolfSSL_SetEccSignCtx()で格納された公開鍵ECC署名コールバックコンテキストを取得できるようにします。

    \return pointer 成功時、コンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSLオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_SetEccSignCtx
*/
void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

/*!
    \brief 呼び出し元が公開鍵ECC署名コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param ctx 格納するユーザコンテキストへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx);

/*!
    \brief 呼び出し元が以前にwolfSSL_SetEccSignCtx()で格納された公開鍵ECC署名コールバックコンテキストを取得できるようにします。

    \return pointer 成功時、コンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストの場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_SetEccSignCtx
*/
void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx);

/*!
    \brief 呼び出し元がECC検証用の公開鍵コールバックを設定できるようにします。コールバックは成功時に0、エラー時に0未満を返す必要があります。sslとctxポインタはユーザの便宜のために利用可能です。sigは検証する署名で、sigSzは署名の長さを示します。hashはメッセージのダイジェストを含む入力バッファで、hashSzはハッシュの長さをバイト単位で示します。resultは検証の結果を格納する出力変数で、成功時は1、失敗時は0です。keyDerはASN1形式のECC秘密鍵で、keySzは鍵の長さをバイト単位で表します。コールバックの例はwolfssl/test.h myEccVerify()にあります。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetEccVerifyCtx
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb);

/*!
    \brief 呼び出し元が公開鍵ECC検証コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元が以前にwolfSSL_SetEccVerifyCtx()で格納された公開鍵ECC検証コールバックコンテキストを取得できるようにします。

    \return pointer 成功時、コンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストの場合に返されます。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_SetEccVerifyCtx
*/
void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

/*!
    \brief 呼び出し元がRSA署名用の公開鍵コールバックを設定できるようにします。コールバックは成功時に0、エラー時に0未満を返す必要があります。sslとctxポインタはユーザの便宜のために利用可能です。inは署名する入力バッファで、inSzは入力の長さを示します。outは署名の結果を格納する出力バッファです。outSzは入出力変数で、呼び出し時の出力バッファのサイズを指定し、返す前に署名の実際のサイズをそこに格納する必要があります。keyDerはASN1形式のRSA秘密鍵で、keySzは鍵の長さをバイト単位で表します。コールバックの例はwolfssl/test.h myRsaSign()にあります。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaSignCtx
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb);

/*!
    \brief 呼び出し元が公開鍵RSA署名コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元が以前にwolfSSL_SetRsaSignCtx()で格納された公開鍵RSA署名コールバックコンテキストを取得できるようにします。

    \return pointer 成功時、コンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストの場合に返されます。

    \param none パラメータなし。
    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_SetRsaSignCtx
*/
void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

/*!
    \brief 呼び出し元がRSA検証用の公開鍵コールバックを設定できるようにします。コールバックは成功時に平文のバイト数、エラー時に0未満を返す必要があります。sslとctxポインタはユーザの便宜のために利用可能です。sigは検証する署名で、sigSzは署名の長さを示します。outは復号プロセスとパディングの後、検証バッファの先頭に設定する必要があります。keyDerはASN1形式のRSA公開鍵で、keySzは鍵の長さをバイト単位で表します。コールバックの例はwolfssl/test.h myRsaVerify()にあります。

    \return none 戻り値なし。

    \param none パラメータなし。

    \sa wolfSSL_SetRsaVerifyCtx
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);/*!
    \brief 呼び出し元が公開鍵RSA検証コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元がwolfSSL_SetRsaVerifyCtx()で以前に保存された公開鍵RSA検証コールバックコンテキストを取得できるようにします。

    \return pointer 成功した場合、呼び出しはコンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストに対して返されます。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_SetRsaVerifyCtx
*/
void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

/*!
    \brief 呼び出し元がRSA公開暗号化のための公開鍵コールバックを設定できるようにします。コールバックは成功の場合は0を、エラーの場合は0未満を返す必要があります。sslとctxポインタはユーザーの利便性のために利用可能です。inは暗号化する入力バッファで、inSzは入力の長さを示します。outは暗号化の結果を格納する出力バッファです。outSzは入出力変数で、呼び出し時に出力バッファのサイズを指定し、戻る前に暗号化の実際のサイズを格納する必要があります。keyDerはASN1形式のRSA公開鍵で、keySzはバイト単位の鍵の長さです。コールバックの例はwolfssl/test.hのmyRsaEnc()にあります。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Examples_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaEncCtx
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb);

/*!
    \brief 呼び出し元が公開鍵RSA公開暗号化コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元がwolfSSL_SetRsaEncCtx()で以前に保存された公開鍵RSA公開暗号化コールバックコンテキストを取得できるようにします。

    \return pointer 成功した場合、呼び出しはコンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストに対して返されます。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_SetRsaEncCtx
*/
void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/*!
    \brief 呼び出し元がRSA秘密復号のための公開鍵コールバックを設定できるようにします。コールバックは成功の場合は平文のバイト数を、エラーの場合は0未満を返す必要があります。sslとctxポインタはユーザーの利便性のために利用可能です。inは復号する入力バッファで、inSzは入力の長さを示します。outは復号処理とパディングの後、復号バッファの先頭に設定する必要があります。keyDerはASN1形式のRSA秘密鍵で、keySzはバイト単位の鍵の長さです。コールバックの例はwolfssl/test.hのmyRsaDec()にあります。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaDecCtx
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb);

/*!
    \brief 呼び出し元が公開鍵RSA秘密復号コールバックコンテキストをctxに設定できるようにします。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief 呼び出し元がwolfSSL_SetRsaDecCtx()で以前に保存された公開鍵RSA秘密復号コールバックコンテキストを取得できるようにします。

    \return pointer 成功した場合、呼び出しはコンテキストへの有効なポインタを返します。
    \return NULL 空のコンテキストに対して返されます。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_SetRsaDecCtx
*/
void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);

/*!
    \brief この関数は、新しいCA証明書がwolfSSLにロードされたときに呼び出されるコールバックをSSLコンテキスト(WOLFSSL_CTX)に登録します。コールバックにはDERエンコードされた証明書を含むバッファが渡されます。

    \return none 戻り値なし。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param callback wolfSSLコンテキストctxのCAコールバックとして登録される関数。この関数のシグネチャは、上記の概要セクションに示されているものに従う必要があります。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;

    // CAコールバックのプロトタイプ
    int MyCACallback(unsigned char *der, int sz, int type);

    // SSLコンテキストにカスタムCAコールバックを登録
    wolfSSL_CTX_SetCACb(ctx, MyCACallback);

    int MyCACallback(unsigned char* der, int sz, int type)
    {
    	// カスタムCAコールバック関数、DERエンコードされた証明書は
        // サイズszの"der"に格納され、タイプは"type"
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
*/
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb);

/*!
    \ingroup CertManager
    \brief 新しい証明書マネージャーコンテキストを割り当て、初期化します。このコンテキストはSSLの必要性とは独立して使用できます。証明書のロード、証明書の検証、失効ステータスのチェックに使用できます。

    \return WOLFSSL_CERT_MANAGER 成功した場合、呼び出しは有効なWOLFSSL_CERT_MANAGERポインタを返します。
    \return NULL エラー状態の場合に返されます。

    \param none パラメータなし。

    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);

/*!
    \ingroup CertManager
    \brief 新しい証明書マネージャーコンテキストを割り当て、初期化します。このコンテキストはSSLの必要性とは独立して使用できます。証明書のロード、証明書の検証、失効ステータスのチェックに使用できます。

    \return WOLFSSL_CERT_MANAGER 成功した場合、呼び出しは有効なWOLFSSL_CERT_MANAGERポインタを返します。
    \return NULL エラー状態の場合に返されます。

    \param none パラメータなし。

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
	    // 新しい証明書マネージャーの作成エラー
    }
    \endcode

    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);

/*!
    \ingroup CertManager
    \brief 証明書マネージャーコンテキストに関連するすべてのリソースを解放します。証明書マネージャーを使用する必要がなくなったときにこれを呼び出します。

    \return none 戻り値なし。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。

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
    \brief マネージャーコンテキストへのCA証明書ロードの場所を指定します。PEM証明書CAfileには複数の信頼されたCA証明書を含めることができます。CApathがNULLでない場合、PEM形式のCA証明書を含むディレクトリを指定します。

    \return SSL_SUCCESS 成功した場合に返されます。
    \return SSL_BAD_FILETYPE ファイルの形式が間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足の状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードが失敗した場合に返されます。
    \return BAD_FUNC_ARG ポインタが提供されていない場合に返されるエラーです。
    \return SSL_FATAL_ERROR 失敗時に返されます。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param file ロードするCA証明書を含むファイル名へのポインタ。
    \param path ロードするCA証明書を含むディレクトリパスの名前へのポインタ。証明書ディレクトリが不要な場合はNULLポインタを使用できます。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerLoadCA(cm, "path/to/cert-file.pem", 0);
    if (ret != SSL_SUCCESS) {
	    // 証明書マネージャーへのCA証明書のロードエラー
    }
    \endcode

    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                 const char* d);

/*!
    \ingroup CertManager
    \brief wolfSSL_CTX_load_verify_bufferを呼び出し、関数に渡されたcmの情報を失わないように一時的なcmを使用してその結果を返すことで、CAバッファをロードします。

    \return SSL_FATAL_ERROR WOLFSSL_CERT_MANAGER構造体がNULL、またはwolfSSL_CTX_new()がNULLを返した場合に返されます。
    \return SSL_SUCCESS 正常に実行された場合に返されます。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param in 証明書情報のバッファ。
    \param sz バッファの長さ。
    \param format 証明書の形式、PEMまたはDER。

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    …
    const unsigned char* in;
    long sz;
    int format;
    …
    if(wolfSSL_CertManagerLoadCABuffer(vp, sz, format) != SSL_SUCCESS){
	    // エラーが返されました。失敗ケースのコードブロック。
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
    \brief この関数はCA署名者リストをアンロードします。

    \return SSL_SUCCESS 関数の正常な実行時に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGERがNULLの場合に返されます。
    \return BAD_MUTEX_E mutexエラーが発生した場合に返されます。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    ...
    if(wolfSSL_CertManagerUnloadCAs(cm) != SSL_SUCCESS){
        // 失敗ケース。
    }
    \endcode

    \sa UnlockMutex
*/
int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief この関数はCA署名者リストに追加された中間証明書をアンロードします。

    \return SSL_SUCCESS 関数の正常な実行時に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGERがNULLの場合に返されます。
    \return BAD_MUTEX_E mutexエラーが発生した場合に返されます。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    ...
    if(wolfSSL_CertManagerUnloadIntermediateCerts(cm) != SSL_SUCCESS){
    	// 失敗ケース。
    }
    \endcode

    \sa UnlockMutex
*/
int wolfSSL_CertManagerUnloadIntermediateCerts(WOLFSSL_CERT_MANAGER* cm);/*!
    \ingroup CertManager
    \brief この関数は、Trusted Peerリンクリストを解放し、トラステッドピアリストのロックを解除します。

    \return SSL_SUCCESS 関数が正常に完了した場合。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGERがNULLの場合。
    \return BAD_MUTEX_E WOLFSSL_CERT_MANAGER構造体のメンバであるtpLockが0(null)の場合、mutexエラー。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    if(wolfSSL_CertManagerUnload_trust_peers(cm) != SSL_SUCCESS){
	    // 関数は正常に実行されませんでした。
    }
    \endcode

    \sa UnLockMutex
*/
int wolfSSL_CertManagerUnload_trust_peers(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief Certificate Managerコンテキストで検証する証明書を指定します。フォーマットはSSL_FILETYPE_PEMまたはSSL_FILETYPE_ASN1を指定できます。

    \return SSL_SUCCESS 成功時。
    \return ASN_SIG_CONFIRM_E 署名を検証できなかった場合に返されます。
    \return ASN_SIG_OID_E 署名タイプがサポートされていない場合に返されます。
    \return CRL_CERT_REVOKED この証明書が失効している場合に返されるエラー。
    \return CRL_MISSING 現在の発行者CRLが利用できない場合に返されるエラー。
    \return ASN_BEFORE_DATE_E 現在の日付がbefore dateより前の場合に返されます。
    \return ASN_AFTER_DATE_E 現在の日付がafter dateより後の場合に返されます。
    \return SSL_BAD_FILETYPE ファイルのフォーマットが間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードに失敗した場合に返されます。
    \return BAD_FUNC_ARG ポインタが提供されていない場合に返されるエラー。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param fname 検証する証明書を含むファイルの名前へのポインタ。
    \param format 検証する証明書のフォーマット - SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerVerify(cm, "path/to/cert-file.pem",
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // 証明書の検証エラー
    }
    \endcode

    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerifyBuffer
*/
int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                    int format);

/*!
    \ingroup CertManager
    \brief Certificate Managerコンテキストで検証する証明書バッファを指定します。フォーマットはSSL_FILETYPE_PEMまたはSSL_FILETYPE_ASN1を指定できます。

    \return SSL_SUCCESS 成功時。
    \return ASN_SIG_CONFIRM_E 署名を検証できなかった場合に返されます。
    \return ASN_SIG_OID_E 署名タイプがサポートされていない場合に返されます。
    \return CRL_CERT_REVOKED この証明書が失効している場合に返されるエラー。
    \return CRL_MISSING 現在の発行者CRLが利用できない場合に返されるエラー。
    \return ASN_BEFORE_DATE_E 現在の日付がbefore dateより前の場合に返されます。
    \return ASN_AFTER_DATE_E 現在の日付がafter dateより後の場合に返されます。
    \return SSL_BAD_FILETYPE ファイルのフォーマットが間違っている場合に返されます。
    \return SSL_BAD_FILE ファイルが存在しない、読み取れない、または破損している場合に返されます。
    \return MEMORY_E メモリ不足状態が発生した場合に返されます。
    \return ASN_INPUT_E ファイルのBase16デコードに失敗した場合に返されます。
    \return BAD_FUNC_ARG ポインタが提供されていない場合に返されるエラー。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param buff 検証する証明書を含むバッファ。
    \param sz バッファbufのサイズ。
    \param format buf内にある検証する証明書のフォーマット - SSL_FILETYPE_ASN1またはSSL_FILETYPE_PEM。

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
    	// 証明書の検証エラー
    }

    \endcode

    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* buff, long sz, int format);

/*!
    \ingroup CertManager
    \brief この関数は、Certificate Manager内にverifyCallback関数を設定します。存在する場合、ロードされた各証明書に対して呼び出されます。検証エラーがある場合、verify callbackを使用してエラーをオーバーライドできます。

    \return none 戻り値はありません。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param verify_callback コールバックルーチンへのVerifyCallback関数ポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
    { // 証明書のカスタム検証を実行 }

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    wolfSSL_CertManagerSetVerify(cm, myVerify);

    \endcode

    \sa wolfSSL_CertManagerVerify
*/
void wolfSSL_CertManagerSetVerify(WOLFSSL_CERT_MANAGER* cm,
        VerifyCallback verify_callback);

/*!
    \brief オプションが有効な場合、CRLをチェックし、証明書をCRLリストと比較します。

    \return SSL_SUCCESS 関数が期待どおりに戻った場合に返されます。WOLFSSL_CERT_MANAGER構造体のcrlEnabledメンバがオンになっている場合。
    \return MEMORY_E 割り当てられたメモリが失敗した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGERがNULLの場合。

    \param cm WOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param der DERフォーマットの証明書へのポインタ。
    \param sz 証明書のサイズ。

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm;
    byte* der;
    int sz; // derのサイズ
    ...
    if(wolfSSL_CertManagerCheckCRL(cm, der, sz) != SSL_SUCCESS){
    	// エラーが返されました。失敗ケースを処理。
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
    \brief Certificate Managerで証明書を検証する際に、Certificate Revocation Listチェックをオンにします。デフォルトでは、CRLチェックはオフです。optionsには、リーフ証明書のみ(デフォルト)ではなくチェーン内の各証明書に対してCRLチェックを実行するWOLFSSL_CRL_CHECKALLが含まれます。

    \return SSL_SUCCESS 成功した場合、呼び出しは戻ります。
    \return NOT_COMPILED_IN wolfSSLがCRLを有効にしてビルドされていない場合に返されます。
    \return MEMORY_E メモリ不足状態が発生した場合に返されます。
    \return BAD_FUNC_ARG ポインタが提供されていない場合に返されるエラー。
    \return SSL_FAILURE CRLコンテキストを適切に初期化できない場合に返されます。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param options Certification Manager(cm)を有効にする際に使用するオプション。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerEnableCRL(cm, 0);
    if (ret != SSL_SUCCESS) {
    	// cert managerの有効化エラー
    }

    ...
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief Certificate Managerで証明書を検証する際に、Certificate Revocation Listチェックをオフにします。デフォルトでは、CRLチェックはオフです。この関数を使用して、以前にCRLチェックを有効にしていたこのCertificate Managerコンテキストに対して、CRLチェックを一時的または永続的に無効にできます。

    \return SSL_SUCCESS 成功した場合、呼び出しは戻ります。
    \return BAD_FUNC_ARG 関数ポインタが提供されていない場合に返されるエラー。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerDisableCRL(cm);
    if (ret != SSL_SUCCESS) {
    	// cert managerの無効化エラー
    }
    ...
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
*/
int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief エラーチェックを行い、LoadCRL()に渡して失効チェックのためにCRLに証明書をロードします。更新されたCRLをロードするには、まずwolfSSL_CertManagerFreeCRLを呼び出してから、新しいCRLをロードします。

    \return SSL_SUCCESS wolfSSL_CertManagerLoadCRLにエラーがなく、LoadCRLが正常に戻った場合。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合。
    \return SSL_FATAL_ERROR wolfSSL_CertManagerEnableCRLがSSL_SUCCESS以外を返した場合。
    \return BAD_PATH_ERROR pathがNULLの場合。
    \return MEMORY_E LoadCRLがヒープメモリの割り当てに失敗した場合。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param path CRLパスを保持する定数char型ポインタ。
    \param type ロードする証明書のタイプ。
    \param monitor LoadCRL()での監視を要求します。

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
    \sa wolfSSL_CertManagerFreeCRL
*/
int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER* cm,
                               const char* path, int type, int monitor);

/*!
    \ingroup CertManager
    \brief この関数は、BufferLoadCRLを呼び出してCRLファイルをロードします。

    \return SSL_SUCCESS 関数がエラーなく完了した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGERがNULLの場合に返されます。
    \return SSL_FATAL_ERROR WOLFSSL_CERT_MANAGERに関連するエラーがある場合に返されます。

    \param cm WOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param buff 定数byte型でバッファです。
    \param sz バッファのサイズを表すlong int型。
    \param type 証明書タイプを保持するlong integer型。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    const unsigned char* buff;
    long sz; バッファのサイズ
    int type;  証明書タイプ
    ...
    int ret = wolfSSL_CertManagerLoadCRLBuffer(cm, buff, sz, type);
    if(ret == SSL_SUCCESS){
	    return ret;
    } else {
    	// 失敗ケース。
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
    \brief この関数は、CRL Certificate Managerコールバックを設定します。HAVE_CRLが定義されており、一致するCRLレコードが見つからない場合、cbMissingCRLが呼び出されます(wolfSSL_CertManagerSetCRL_Cbで設定)。これにより、外部からCRLを取得してロードできます。

    \return SSL_SUCCESS 関数とサブルーチンの実行が成功した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。

    \param cm 証明書の情報を保持するWOLFSSL_CERT_MANAGER構造体。
    \param cb WOLFSSL_CERT_MANAGERのcbMissingCRLメンバに設定される(*CbMissingCRL)への関数ポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url){
	    // 関数本体。
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
    \brief この関数は、CRL更新コールバックを設定します。HAVE_CRLとHAVE_CRL_UPDATE_CBが定義されており、CRLが追加されるときに同じ発行者でより低いCRL番号を持つエントリが存在する場合、既存のエントリと、それを置き換える新しいエントリの詳細と共にCbUpdateCRLが呼び出されます。

    \return SSL_SUCCESS 関数とサブルーチンが正常に実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。

    \param cm 証明書の情報を保持するWOLFSSL_CERT_MANAGER構造体。
    \param cb WOLFSSL_CERT_MANAGERのcbUpdateCRLメンバに設定される(*CbUpdateCRL)への関数ポインタ。
    シグネチャ要件:
	void (*CbUpdateCRL)(CrlInfo *old, CrlInfo *new);

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(CrlInfo *old, CrlInfo *new){
	    // 関数本体。
    }
    …
    CbUpdateCRL cb = CbUpdateCRL;
    …
    if(ctx){
        return wolfSSL_CertManagerSetCRLUpdate_Cb(SSL_CM(ssl), cb);
    }
    \endcode

    \sa CbUpdateCRL
*/
int wolfSSL_CertManagerSetCRLUpdate_Cb(WOLFSSL_CERT_MANAGER* cm,
                                       CbUpdateCRL cb);

/*!
    \ingroup CertManager
    \brief この関数は、エンコードされたCRLバッファから解析されたCRL情報を含む構造体を生成します。

    \return SSL_SUCCESS 関数とサブルーチンが正常に実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。

    \param cm   WOLFSSL_CERT_MANAGER構造体。
    \param info CRL情報を受け取る呼び出し元管理のCrlInfo構造体へのポインタ。
    \param buff エンコードされたCRLを含む入力バッファ。
    \param sz   buff内の入力CRLデータの長さ(バイト単位)。
    \param type WOLFSSL_FILETYPE_PEMまたはWOLFSSL_FILETYPE_DER

    _Example_
    \code
    #include <wolfssl/ssl.h>

    CrlInfo info;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    cm = wolfSSL_CertManagerNew();

    // ファイルからバッファへcrlデータを読み込む

    wolfSSL_CertManagerGetCRLInfo(cm, &info, crlData, crlDataLen,
                                  WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa CbUpdateCRL
    \sa wolfSSL_SetCRL_Cb
*/
int wolfSSL_CertManagerGetCRLInfo(WOLFSSL_CERT_MANAGER* cm, CrlInfo* info,
    const byte* buff, long sz, int type)

/*!
    \ingroup CertManager
    \brief この関数は、証明書マネージャに保存されているCRLを解放します。アプリケーションは、wolfSSL_CertManagerFreeCRLを呼び出してから新しいCRLを読み込むことで、CRLを更新できます。

    \return SSL_SUCCESS 関数とサブルーチンが正常に実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。

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
    \brief この関数は、WOLFSSL_CERT_MANAGERのメンバであるocspEnabledを有効にして、OCSPチェックオプションが有効になっていることを示します。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。WOLFSSL_CERT_MANAGERのocspEnabledメンバが有効になります。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合、またはサブルーチンに許可されていない引数値が渡された場合に返されます。
    \return MEMORY_E この関数またはサブルーチン内でメモリの割り当てにエラーがある場合に返されます。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param der 証明書へのbyteポインタ。
    \param sz DER証明書のサイズを表すint型。

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* der;
    int sz; // derのサイズ
    ...
    if(wolfSSL_CertManagerCheckOCSP(cm, der, sz) != SSL_SUCCESS){
	    // 失敗ケース。
    }
    \endcode

    \sa ParseCertRelative
    \sa CheckCertOCSP
*/
int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER* cm,
                                 unsigned char* der, int sz);

/*!
    \ingroup CertManager
    \brief OCSPがオフになっている場合にオンにし、設定オプションでコンパイルされている場合に有効にします。

    \return SSL_SUCCESS 関数呼び出しが成功した場合に返されます。
    \return BAD_FUNC_ARG cm構造体がNULLの場合。
    \return MEMORY_E WOLFSSL_OCSP構造体の値がNULLの場合。
    \return SSL_FAILURE WOLFSSL_OCSP構造体の初期化が失敗した場合。
    \return NOT_COMPILED_IN 正しい機能を有効にしてコンパイルされていないビルド。

    \param cm wolfSSL_CertManagerNew()を使用して作成されたWOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param options WOLFSSL_CERT_MANAGER構造体の値を設定するために使用されます。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    int options;
    …
    if(wolfSSL_CertManagerEnableOCSP(SSL_CM(ssl), options) != SSL_SUCCESS){
	    // 失敗ケース。
    }
    \endcode

    \sa wolfSSL_CertManagerNew
*/
int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief OCSP証明書失効を無効にします。

    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRLがWOLFSSL_CERT_MANAGER構造体のcrlEnabledメンバを正常に無効にしました。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLでした。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CertManagerDisableOCSP(ssl) != SSL_SUCCESS){
	    // 失敗ケース。
    }
    \endcode

    \sa wolfSSL_DisableCRL
*/
int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief この関数は、URLをWOLFSSL_CERT_MANAGER構造体のocspOverrideURLメンバにコピーします。

    \return SSL_SUCCESS 関数が期待通りに実行できた場合。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合。
    \return MEMEORY_E 証明書マネージャのocspOverrideURLメンバにメモリを割り当てることができなかった場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    #include <wolfssl/ssl.h>
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    const char* url;
    …
    int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
    …
    if(wolfSSL_CertManagerSetOCSPOverrideURL(SSL_CM(ssl), url) != SSL_SUCCESS){
	    // 失敗ケース。
    }
    \endcode

    \sa ocspOverrideURL
    \sa wolfSSL_SetOCSP_OverrideURL
*/
int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER* cm,
                                          const char* url);

/*!
    \ingroup CertManager
    \brief この関数は、WOLFSSL_CERT_MANAGER内のOCSPコールバックを設定します。

    \return SSL_SUCCESS 実行が成功した場合に返されます。引数はWOLFSSL_CERT_MANAGER構造体に保存されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGERがNULLの場合に返されます。

    \param cm WOLFSSL_CERT_MANAGER構造体へのポインタ。
    \param ioCb CbOCSPIO型の関数ポインタ。
    \param respFreeCb CbOCSPRespFree型の関数ポインタ。
    \param ioCbCtx I/Oコールバックユーザ登録コンテキストへのvoidポインタ変数。

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
    \sa wolfSSL_EnableOCSP
    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_SetOCSP_Cb
*/
int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER* cm,
                                  CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                                  void* ioCbCtx);

/*!
    \ingroup CertManager
    \brief この関数は、OCSPステープリングがオンになっていない場合にオンにし、オプションを設定します。

    \return SSL_SUCCESS エラーがなく、関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGER構造体がNULLの場合、またはサブルーチンに許可されていない引数値が渡された場合に返されます。
    \return MEMORY_E メモリの割り当てに問題があった場合に返されます。
    \return SSL_FAILURE OCSP構造体の初期化が失敗した場合に返されます。
    \return NOT_COMPILED_IN wolfSSLがHAVE_CERTIFICATE_STATUS_REQUESTオプションでコンパイルされていない場合に返されます。

    \param cm WOLFSSL_CTX構造体のメンバであるWOLFSSL_CERT_MANAGER構造体へのポインタ。

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
    \brief CRL証明書失効を有効にします。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなく返された場合。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合に返されます。
    \return MEMORY_E メモリの割り当てが失敗した場合に返されます。
    \return SSL_FAILURE InitCRL関数が正常に返されなかった場合に返されます。
    \return NOT_COMPILED_IN コンパイル時にHAVE_CRLが有効になっていませんでした。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param options WOLFSSL_CERT_MANAGER構造体のcrlCheckAllメンバの設定を決定するために使用される整数。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_EnableCRL(ssl, WOLFSSL_CRL_CHECKALL) != SSL_SUCCESS){
	    // 失敗ケース。この関数またはサブルーチンがSSL_SUCCESSを返しませんでした。
    }
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
*/
int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);

/*!
    \brief CRL証明書失効を無効にします。

    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRLがWOLFSSL_CERT_MANAGER構造体のcrlEnabledメンバを正常に無効にしました。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLでした。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_DisableCRL(ssl) != SSL_SUCCESS){
    	// 失敗ケース
    }
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableCRL(WOLFSSL* ssl);

/*!
    \brief 失効チェックのための証明書を読み込むためにLoadCRLを最終的に呼び出すラッパー関数です。

    \return WOLFSSL_SUCCESS 関数とすべてのサブルーチンがエラーなく実行された場合に返されます。
    \return SSL_FATAL_ERROR サブルーチンの1つが正常に返されなかった場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CERT_MANAGERまたはWOLFSSL構造体がNULLの場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param path crlファイルへのパスを保持する定数文字ポインタ。
    \param type 証明書のタイプを表す整数。
    \param monitor 要求された場合にモニタパスを検証するために使用される整数変数。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* crlPemDir;
    …
    if(wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS){
    	// 失敗ケース。SSL_SUCCESSを返しませんでした。
    }
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
    \sa LoadCRL
*/
int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor);

/*!
    \brief WOLFSSL_CERT_MANAGER構造体内のCRLコールバックを設定します。

    \return SSL_SUCCESS 関数またはサブルーチンがエラーなく実行された場合に返されます。WOLFSSL_CERT_MANAGERのcbMissingCRLメンバが設定されます。
    \return BAD_FUNC_ARG WOLFSSLまたはWOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb CbMissingCRLへの関数ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url) // 必要なシグネチャ
    {
        // 関数本体
    }
    …
    int crlCb = wolfSSL_SetCRL_Cb(ssl, cb);
    if(crlCb != SSL_SUCCESS){
    	// コールバックが正しく設定されませんでした
    }
    \endcode

    \sa CbMissingCRL
    \sa wolfSSL_CertManagerSetCRL_Cb
*/
int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb);

/*!
    \brief この関数は、OCSP証明書検証を有効にします。optionsの値は、以下のオプションの1つ以上をOR演算することで形成されます。
    WOLFSSL_OCSP_URL_OVERRIDE - 証明書内のURLの代わりにオーバーライドURLを使用します。オーバーライドURLはwolfSSL_CTX_SetOCSP_OverrideURL()関数を使用して指定されます。
    WOLFSSL_OCSP_CHECKALL - すべてのOCSPチェックをオンに設定します。
    WOLFSSL_OCSP_NO_NONCE - OCSP要求作成時のnonceオプションを設定します。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG この関数またはサブルーチンの引数が無効な引数値を受け取った場合に返されます。
    \return MEMORY_E 構造体または他の変数のメモリ割り当てでエラーが発生した場合に返されます。
    \return NOT_COMPILED_IN wolfSSLがHAVE_OCSPオプション付きでコンパイルされていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param options 設定チェックに使用されるwolfSSL_CertMangerENableOCSP()に渡される整数型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int options; // オプション定数で初期化
    …
    int ret = wolfSSL_EnableOCSP(ssl, options);
    if(ret != SSL_SUCCESS){
    	// OCSPが有効になっていません
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSP
*/
int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options);

/*!
    \brief OCSP証明書失効オプションを無効にします。

    \return SSL_SUCCESS 関数とそのサブルーチンがエラーなしで返された場合に返されます。WOLFSSL_CERT_MANAGER構造体のocspEnabledメンバが正常に設定されました。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(wolfSSL_DisableOCSP(ssl) != SSL_SUCCESS){
	    // エラーで返されました。このブロック内が失敗ケースです
    }
    \endcode

    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableOCSP(WOLFSSL*);

/*!
    \brief この関数は、WOLFSSL_CERT_MANAGER構造体のocspOverrideURLメンバを設定します。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合、またはサブルーチンに許可されていない引数が渡された場合に返されます。
    \return MEMORY_E サブルーチンでメモリ割り当てエラーが発生した場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param url WOLFSSL_CERT_MANAGER構造体のocspOverrideURLメンバに格納されるURLへの定数charポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char url[URLSZ];
    ...
    if(wolfSSL_SetOCSP_OverrideURL(ssl, url)){
    	// オーバーライドURLが新しい値に設定されました
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSPOverrideURL
*/
int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url);

/*!
    \brief この関数は、WOLFSSL_CERT_MANAGER構造体にOCSPコールバックを設定します。

    \return SSL_SUCCESS 関数がエラーなしで実行された場合に返されます。CMのocspIOCb、ocspRespFreeCb、ocspIOCtxメンバが設定されます。
    \return BAD_FUNC_ARG WOLFSSLまたはWOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param ioCb CbOCSPIO型への関数ポインタ。
    \param respFreeCb CbOCSPRespFree型への関数ポインタで、レスポンスメモリを解放する呼び出しです。
    \param ioCbCtx CMのocspIOCtxメンバに保持されるvoidポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int OCSPIO_CB(void* , const char*, int , unsigned char* , int,
    unsigned char**){  // このシグネチャが必要です
        // 関数本体
    }
    …
    void OCSPRespFree_CB(void* , unsigned char* ){ // このシグネチャが必要です
    	// 関数本体
    }
    …
    void* ioCbCtx;
    CbOCSPRespFree CB_OCSPRespFree;

    if(wolfSSL_SetOCSP_Cb(ssl, OCSPIO_CB( pass args ), CB_OCSPRespFree,
				ioCbCtx) != SSL_SUCCESS){
	    // コールバックが設定されませんでした
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                       void* ioCbCtx);

/*!
    \brief CTXを通じてCRL証明書検証を有効にします。

    \return SSL_SUCCESS この関数とそのサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG CTX構造体がNULLの場合、またはサブルーチンで無効な引数が渡された場合に返されます。
    \return MEMORY_E 関数の実行中にメモリ割り当てエラーが発生した場合に返されます。
    \return SSL_FAILURE WOLFSSL_CERT_MANAGERのcrlメンバが正しく初期化できなかった場合に返されます。
    \return NOT_COMPILED_IN wolfSSLがHAVE_CRLオプション付きでコンパイルされていません。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_EnableCRL(ssl->ctx, options) != SSL_SUCCESS){
    	// 関数が失敗しました
    }
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
    \sa wolfSSL_CTX_DisableCRL
*/
int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);

/*!
    \brief この関数は、CTX構造体でCRL検証を無効にします。

    \return SSL_SUCCESS 関数がエラーなしで実行された場合に返されます。WOLFSSL_CERT_MANAGER構造体のcrlEnabledメンバが0に設定されます。
    \return BAD_FUNC_ARG CTX構造体またはCM構造体のいずれかがNULL値の場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_DisableCRL(ssl->ctx) != SSL_SUCCESS){
    	// 失敗ケース
    }
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);

/*!
    \brief この関数は、wolfSSL_CertManagerLoadCRL()を通じてCRLをWOLFSSL_CTX構造体にロードします。

    \return SSL_SUCCESS - 関数とそのサブルーチンがエラーなしで実行された場合に返されます。
    \return BAD_FUNC_ARG - この関数またはサブルーチンにNULL構造体が渡された場合に返されます。
    \return BAD_PATH_ERROR - path変数がNULLとして開かれた場合に返されます。
    \return MEMORY_E - メモリの割り当てが失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param path 証明書へのパス。
    \param type 証明書のタイプを保持する整数変数。
    \param monitor モニタパスが要求されているかを判定するために使用される整数変数。

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
    \brief この関数は、wolfSSL_CertManagerSetCRL_Cbを呼び出すことにより、コールバック引数をWOLFSSL_CERT_MANAGER構造体のcbMissingCRLメンバに設定します。

    \return SSL_SUCCESS 実行が成功した場合に返されます。WOLFSSL_CERT_MANAGER構造体のメンバcbMssingCRLがcbに正常に設定されました。
    \return BAD_FUNC_ARG WOLFSSL_CTXまたはWOLFSSL_CERT_MANAGERがNULLの場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param cb CbMissingCRL型のコールバック関数へのポインタ。
    シグネチャ要件:
	void (*CbMissingCRL)(const char* url);

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    void cb(const char* url) // 必要なシグネチャ
    {
    	// 関数本体
    }
    …
    if (wolfSSL_CTX_SetCRL_Cb(ctx, cb) != SSL_SUCCESS){
    	// 失敗ケース、cbが正しく設定されませんでした
    }
    \endcode

    \sa wolfSSL_CertManagerSetCRL_Cb
    \sa CbMissingCRL
*/
int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb);

/*!
    \brief この関数は、wolfSSLのOCSP機能の動作を設定するオプションを設定します。optionsの値は、以下のオプションの1つ以上をOR演算することで形成されます。
    WOLFSSL_OCSP_URL_OVERRIDE - 証明書内のURLの代わりにオーバーライドURLを使用します。オーバーライドURLはwolfSSL_CTX_SetOCSP_OverrideURL()関数を使用して指定されます。
    WOLFSSL_OCSP_CHECKALL - すべてのOCSPチェックをオンに設定します。
    WOLFSSL_OCSP_NO_NONCE - OCSP要求作成時のnonceオプションを設定します。

    この関数は、wolfSSLがOCSPサポート付きでコンパイルされている場合(--enable-ocsp、#define HAVE_OCSP)にのみOCSPオプションを設定します。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FAILURE 失敗時に返されます。
    \return NOT_COMPILED_IN この関数が呼び出されたが、wolfSSLのコンパイル時にOCSPサポートが有効になっていなかった場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param options OCSPオプションを設定するために使用される値。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    int options; // オプション定数で初期化
    …
    int ret = wolfSSL_CTX_EnableOCSP(ctx, options);
    if(ret != SSL_SUCCESS){
        // OCSPが有効になっていません
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSP
    \sa wolfSSL_EnableOCSP
*/
int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options);

/*!
    \brief この関数は、WOLFSSL_CERT_MANAGER構造体のocspEnabledメンバに影響を与えることにより、OCSP証明書失効チェックを無効にします。

    \return SSL_SUCCESS 関数がエラーなしで実行された場合に返されます。CMのocspEnabledメンバが無効にされました。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(!wolfSSL_CTX_DisableOCSP(ssl->ctx)){
    	// OCSPが無効になっていません
    }
    \endcode

    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX*);

/*!
    \brief この関数は、OCSPが使用するURLを手動で設定します。デフォルトでは、wolfSSL_CTX_EnableOCSPを使用してWOLFSSL_OCSP_URL_OVERRIDEオプションが設定されていない限り、OCSPは個々の証明書で見つかったURLを使用します。

    \return SSL_SUCCESS 成功時に返されます。
    \return SSL_FAILURE 失敗時に返されます。
    \return NOT_COMPILED_IN この関数が呼び出されたが、wolfSSLのコンパイル時にOCSPサポートが有効になっていなかった場合に返されます。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param url wolfSSLが使用するOCSP URLへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_OCSP_set_override_url(ctx, "custom-url-here");
    \endcode

    \sa wolfSSL_CTX_OCSP_set_options
*/
int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url);

/*!
    \brief WOLFSSL_CTX構造体にOCSPのコールバックを設定します。

    \return SSL_SUCCESS 関数が正常に実行された場合に返されます。CM内のocspIOCb、ocspRespFreeCb、ocspIOCtxメンバが正常に設定されました。
    \return BAD_FUNC_ARG WOLFSSL_CTXまたはWOLFSSL_CERT_MANAGER構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param ioCb 関数ポインタであるCbOCSPIO型。
    \param respFreeCb 関数ポインタであるCbOCSPRespFree型。
    \param ioCbCtx WOLFSSL_CERT_MANAGERに保持されるvoidポインタ。

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
    	// 関数が正常に返されませんでした
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
    \brief この関数は、wolfSSL_CertManagerEnableOCSPStapling()を呼び出してOCSPステープリングを有効にします。
    \return SSL_SUCCESS エラーがなく、関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULL、またはサブルーチンに許可されていない引数値が渡された場合に返されます。
    \return MEMORY_E メモリの割り当てに問題があった場合に返されます。
    \return SSL_FAILURE OCSP構造体の初期化が失敗した場合に返されます。
    \return NOT_COMPILED_IN wolfSSLがHAVE_CERTIFICATE_STATUS_REQUESTオプション付きでコンパイルされていない場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = WOLFSSL_new();
    ssl->method.version; // 希望するプロトコルに設定
    ...
    if(!wolfSSL_CTX_EnableOCSPStapling(ssl->ctx)){
    	// OCSPステープリングが有効になっていません
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa InitOCSP
*/
int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX*);

/*!
    \ingroup CertsKeys

    \brief 通常、SSLハンドシェイクの終了時に、wolfSSLは一時配列を解放します。ハンドシェイクが始まる前にこの関数を呼び出すと、wolfSSLは一時配列を解放しなくなります。一時配列はwolfSSL_get_keys()やPSKヒントなどに必要になる場合があります。ユーザーが一時配列を使い終わったら、wolfSSL_FreeArrays()を呼び出してリソースを即座に解放するか、あるいは関連するSSLオブジェクトが解放されるときにリソースが解放されます。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

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

    \brief 通常、SSLハンドシェイクの終了時に、wolfSSLは一時配列を解放します。ハンドシェイクの前にwolfSSL_KeepArrays()が呼び出されていた場合、wolfSSLは一時配列を解放しません。この関数は一時配列を明示的に解放し、ユーザーが一時配列を使い終わり、SSLオブジェクトが解放されるのを待たずにこれらのリソースを解放したい場合に呼び出す必要があります。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

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
    \brief この関数は、'ssl'パラメータで渡されたSSLオブジェクトでServer Name Indicationの使用を有効にします。つまり、wolfSSLクライアントはClientHelloでSNI拡張を送信し、wolfSSLサーバーはSNI不一致の場合、ClientHello + SNIに対してServerHello + 空のSNIまたはfatalアラートで応答します。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラーです。sslがNULL、dataがNULL、typeが未知の値(以下を参照)。
    \return MEMORY_E メモリが不足している場合に返されるエラーです。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param type dataで渡されるサーバー名のタイプを示します。既知のタイプは、enum { WOLFSSL_SNI_HOST_NAME = 0 }です。
    \param data サーバー名データへのポインタ。
    \param size サーバー名データのサイズ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキスト作成失敗
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl作成失敗
    }
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni使用失敗
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseSNI
*/
int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief この関数は、'ctx'パラメータで渡されたSSLコンテキストから作成されたSSLオブジェクトに対してServer Name Indicationの使用を有効にします。つまり、wolfSSLクライアントはClientHelloでSNI拡張を送信し、wolfSSLサーバーはSNI不一致の場合、ClientHello + SNIに対してServerHello + 空のSNIまたはfatalアラートで応答します。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラーです。ctxがNULL、dataがNULL、typeが未知の値(以下を参照)。
    \return MEMORY_E メモリが不足している場合に返されるエラーです。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param type dataで渡されるサーバー名のタイプを示します。既知のタイプは、enum { WOLFSSL_SNI_HOST_NAME = 0 }です。
    \param data サーバー名データへのポインタ。
    \param size サーバー名データのサイズ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキスト作成失敗
    }
    ret = wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni使用失敗
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSNI
*/
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief この関数は、'ssl'パラメータで渡されたSSLオブジェクトでServer Name Indicationを使用するSSLセッションの動作を設定するために、サーバー側で呼び出されます。オプションについては以下で説明します。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param type dataで渡されるサーバー名のタイプを示します。既知のタイプは、enum { WOLFSSL_SNI_HOST_NAME = 0 }です。
    \param options 選択されたオプションを含むビット単位のセマフォ。利用可能なオプションは、enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01, WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }です。通常、クライアントから提供されたホスト名がサーバーと一致しない場合、サーバーはfatalレベルのunrecognized_name(112)アラートを送信してハンドシェイクを中止します。
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH このオプションが設定されている場合、サーバーはセッションを中止する代わりにSNI応答を送信しません。
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH このオプションが設定されている場合、サーバーはセッションを中止する代わりに、ホスト名が一致しているかのようにSNI応答を送信します。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキスト作成失敗
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl作成失敗
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni使用失敗
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
    \brief この関数は、'ctx'パラメータで渡されたSSLコンテキストから作成されたSSLオブジェクトに対してServer Name Indicationを使用するSSLセッションの動作を設定するために、サーバー側で呼び出されます。オプションについては以下で説明します。

    \return none 戻り値なし。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param type dataで渡されるサーバー名のタイプを示します。既知のタイプは、enum { WOLFSSL_SNI_HOST_NAME = 0 }です。
    \param options 選択されたオプションを含むビット単位のセマフォ。利用可能なオプションは、enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01, WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }です。通常、クライアントから提供されたホスト名がサーバーと一致しない場合、サーバーはfatalレベルのunrecognized_name(112)アラートを送信してハンドシェイクを中止します。
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH このオプションが設定されている場合、サーバーはセッションを中止する代わりにSNI応答を送信しません。
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH このオプションが設定されている場合、サーバーはセッションを中止する代わりに、ホスト名が一致しているかのようにSNI応答を送信します。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
       // コンテキスト作成失敗
    }
    ret = wolfSSL_CTX_UseSNI(ctx, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni使用失敗
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
    \brief この関数は、クライアントがセッションを開始するために送信したClient Helloメッセージからクライアントによって提供されたServer Name Indicationを取得するために、サーバー側で呼び出されます。SNIを取得するためにコンテキストやセッションのセットアップは必要ありません。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラーです。bufferがNULL、bufferSz <= 0、sniがNULL、inOutSzがNULLまたは<= 0。
    \return BUFFER_ERROR 不正な形式のClient Helloメッセージがある場合に返されるエラーです。
    \return INCOMPLETE_DATA 抽出を完了するのに十分なデータがない場合に返されるエラーです。

    \param buffer クライアントから提供されたデータ(Client Hello)へのポインタ。
    \param bufferSz Client Helloメッセージのサイズ。
    \param type bufferから取得されるサーバー名のタイプを示します。既知のタイプは、enum { WOLFSSL_SNI_HOST_NAME = 0 }です。
    \param sni 出力が格納される場所へのポインタ。
    \param inOutSz 出力サイズへのポインタ。この値はMIN("SNIの長さ", inOutSz)に更新されます。

    _Example_
    \code
    unsigned char buffer[1024] = {0};
    unsigned char result[32]   = {0};
    int           length       = 32;
    // Client Helloをbufferに読み込み...
    ret = wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer), 0, result, &length);
    if (ret != WOLFSSL_SUCCESS) {
        // sni取得失敗
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

    \brief この関数はSNIオブジェクトのステータスを取得します。

    \return value SNIがNULLでない場合、この関数はSNI構造体のstatusメンバーのバイト値を返します。
    \return 0 SNIオブジェクトがNULLの場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param type SNIタイプ。

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
    \brief この関数は、SSLセッションでクライアントによって提供されたServer Name Indicationを取得するために、サーバー側で呼び出されます。

    \return size 提供されたSNIデータのサイズ。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param type dataで取得されるサーバー名のタイプを示します。既知のタイプは、enum { WOLFSSL_SNI_HOST_NAME = 0 }です。
    \param data クライアントから提供されたデータへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキスト作成失敗
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl作成失敗
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni使用失敗
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

    \brief wolfSSLセッションでALPNの使用をセットアップします。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG sslまたはprotocol_name_listがnull、またはprotocol_name_listSzが大きすぎる、またはoptionsがサポートされていない何かを含む場合に返されます。
    \return MEMORY_ERROR プロトコルリストのメモリ割り当てエラー。
    \return SSL_FAILURE 失敗時。

    \param ssl 使用するwolfSSLセッション。
    \param protocol_name_list 使用するプロトコル名のリスト。カンマ区切りの文字列が必要です。
    \param protocol_name_listSz プロトコル名リストのサイズ。
    \param options WOLFSSL_ALPN_CONTINUE_ON_MISMATCHまたはWOLFSSL_ALPN_FAILED_ON_MISMATCH。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // 任意のwolfSSLメソッド
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    char alpn_list[] = {};    if (wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
        WOLFSSL_APN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
       // セッションチケット設定エラー
    }
    \endcode

    \sa TLSX_UseALPN
*/
int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
                                unsigned int protocol_name_listSz,
                                unsigned char options);

/*!
    \ingroup TLS

    \brief この関数は、サーバーによって設定されたプロトコル名を取得します。

    \return SSL_SUCCESS エラーがスローされずに正常に実行された場合に返されます。
    \return SSL_FATAL_ERROR 拡張が見つからなかった場合、またはピアとのプロトコルマッチがなかった場合に返されます。また、受け入れられたプロトコル名が複数ある場合にもエラーがスローされます。
    \return SSL_ALPN_NOT_FOUND ピアとのプロトコルマッチが見つからなかったことを示して返されます。
    \return BAD_FUNC_ARG 関数にNULL引数が渡された場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param protocol_name プロトコル名を表し、ALPN構造体に保持されるcharへのポインタ。
    \param size protocol_nameのサイズを表すword16型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int err;
    char* protocol_name = NULL;
    Word16 protocol_nameSz = 0;
    err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);

    if(err == SSL_SUCCESS){
	    // ALPNプロトコルを送信
    }
    \endcode

    \sa TLSX_ALPN_GetRequest
    \sa TLSX_Find
*/
int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name,
                                         unsigned short *size);

/*!
    \ingroup TLS

    \brief この関数は、SSLオブジェクトからalpn_client_listデータをバッファにコピーします。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。SSLオブジェクトのalpn_client_listメンバがlistパラメータにコピーされました。
    \return BAD_FUNC_ARG listまたはlistSzパラメータがNULLの場合に返されます。
    \return BUFFER_ERROR listバッファに問題がある場合に返されます(NULLであるか、サイズが0の場合)。
    \return MEMORY_ERROR メモリの動的割り当てに問題があった場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param list バッファへのポインタ。SSLオブジェクトからのデータがここにコピーされます。
    \param listSz バッファサイズ。

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
	    // クライアントが送信したプロトコル名のリスト
    }
    \endcode

    \sa wolfSSL_UseALPN
*/
int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list,
                                             unsigned short *listSz);

/*!
    \brief この関数は、'ssl'パラメータで渡されたSSLオブジェクトでMaximum Fragment Lengthの使用を有効にするために、クライアント側で呼び出されます。これは、wolfSSLクライアントによってClientHelloでMaximum Fragment Length拡張が送信されることを意味します。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラー: sslがNULL、mflが範囲外。
    \return MEMORY_E メモリが不足している場合に返されるエラー。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param mfl セッションに要求されるMaximum Fragment Lengthを示します。利用可能なオプションは: enum { WOLFSSL_MFL_2_9  = 1, 512バイト WOLFSSL_MFL_2_10 = 2, 1024バイト WOLFSSL_MFL_2_11 = 3, 2048バイト WOLFSSL_MFL_2_12 = 4, 4096バイト WOLFSSL_MFL_2_13 = 5, 8192バイト wolfSSL専用!!! };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキストの作成に失敗
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // sslの作成に失敗
    }
    ret = wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragmentの使用に失敗
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseMaxFragment(WOLFSSL* ssl, unsigned char mfl);

/*!
    \brief この関数は、'ctx'パラメータで渡されたSSLコンテキストから作成されたSSLオブジェクトに対してMaximum Fragment Lengthの使用を有効にするために、クライアント側で呼び出されます。これは、wolfSSLクライアントによってClientHelloでMaximum Fragment Length拡張が送信されることを意味します。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラー: ctxがNULL、mflが範囲外。
    \return MEMORY_E メモリが不足している場合に返されるエラー。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param mfl セッションに要求されるMaximum Fragment Lengthを示します。利用可能なオプションは: enum { WOLFSSL_MFL_2_9  = 1 512バイト、WOLFSSL_MFL_2_10 = 2 1024バイト、WOLFSSL_MFL_2_11 = 3 2048バイト WOLFSSL_MFL_2_12 = 4 4096バイト、WOLFSSL_MFL_2_13 = 5 8192バイト wolfSSL専用!!!、WOLFSSL_MFL_2_13 = 6 256バイト wolfSSL専用!!! };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキストの作成に失敗
    }
    ret = wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragmentの使用に失敗
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, unsigned char mfl);

/*!
    \brief この関数は、'ssl'パラメータで渡されたSSLオブジェクトでTruncated HMACの使用を有効にするために、クライアント側で呼び出されます。これは、wolfSSLクライアントによってClientHelloでTruncated HMAC拡張が送信されることを意味します。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラー: sslがNULL。
    \return MEMORY_E メモリが不足している場合に返されるエラー。

    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキストの作成に失敗
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // sslの作成に失敗
    }
    ret = wolfSSL_UseTruncatedHMAC(ssl);
    if (ret != 0) {
        // truncated HMACの使用に失敗
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl);

/*!
    \brief この関数は、'ctx'パラメータで渡されたSSLコンテキストから作成されたSSLオブジェクトに対してTruncated HMACの使用を有効にするために、クライアント側で呼び出されます。これは、wolfSSLクライアントによってClientHelloでTruncated HMAC拡張が送信されることを意味します。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラー: ctxがNULL。
    \return MEMORY_E メモリが不足している場合に返されるエラー。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキストの作成に失敗
    }
    ret = wolfSSL_CTX_UseTruncatedHMAC(ctx);
    if (ret != 0) {
        // truncated HMACの使用に失敗
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx);

/*!
    \brief ステープリングはCAに連絡する必要性を排除します。ステープリングは、OCSPで提示される証明書失効チェックのコストを削減します。

    \return SSL_SUCCESS TLSX_UseCertificateStatusRequestがエラーなく実行された場合に返されます。
    \return MEMORY_E メモリの割り当てにエラーがある場合に返されます。
    \return BAD_FUNC_ARG 関数に渡された引数がNULLまたは許容できない値である場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param status_type TLSX_UseCertificateStatusRequest()に渡され、CertificateStatusRequest構造体に格納されるバイト型。
    \param options TLSX_UseCertificateStatusRequest()に渡され、CertificateStatusRequest構造体に格納されるバイト型。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR2_OCSP,
        WOLFSSL_CSR2_OCSP_USE_NONCE) != SSL_SUCCESS){
	    // 失敗ケース
    }
    \endcode

    \sa TLSX_UseCertificateStatusRequest
    \sa wolfSSL_CTX_UseOCSPStapling
*/
int wolfSSL_UseOCSPStapling(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief この関数は、ハンドシェイク中に証明書ステータスを要求します。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULLの場合、またはサブルーチンに許可されていない値が渡された場合に返されます。
    \return MEMORY_E 関数またはサブルーチンがメモリの適切な割り当てに失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param status_type TLSX_UseCertificateStatusRequest()に渡され、CertificateStatusRequest構造体に格納されるバイト型。
    \param options TLSX_UseCertificateStatusRequest()に渡され、CertificateStatusRequest構造体に格納されるバイト型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte statusRequest = 0; // ステータスリクエストを初期化
    …
    switch(statusRequest){
    	case WOLFSSL_CSR_OCSP:
    		if(wolfSSL_CTX_UseOCSPStapling(ssl->ctx, WOLFSSL_CSR_OCSP,
                WOLF_CSR_OCSP_USE_NONCE) != SSL_SUCCESS){
                // UseCertificateStatusRequestが失敗
    }
    // switchケースを続ける
    \endcode

    \sa wolfSSL_UseOCSPStapingV2
    \sa wolfSSL_UseOCSPStapling
    \sa TLSX_UseCertificateStatusRequest
*/
int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief この関数は、OCSPのステータスタイプとオプションを設定します。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなく実行された場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがあった場合に返されます。
    \return BAD_FUNC_ARG 関数またはサブルーチンにNULLまたは許容されない引数が渡された場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param status_type OCSPステータスタイプをロードするバイト型。
    \param options wolfSSL_SNI_SetOptions()とwolfSSL_CTX_SNI_SetOptions()で設定されるOCSPオプションを保持するバイト型。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if (wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP_MULTI, 0) != SSL_SUCCESS){
    	// 正しく実行されませんでした。失敗ケースのコードブロック
    }
    \endcode

    \sa TLSX_UseCertificatStatusRequestV2
    \sa wolfSSL_SNI_SetOptions
    \sa wolfSSL_CTX_SNI_SetOptions
*/
int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief OCSPステープリング用の証明書ステータス要求を作成して初期化します。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなく実行された場合。
    \return BAD_FUNC_ARG WOLFSSL_CTX構造体がNULL、またはside変数がクライアント側でない場合に返されます。
    \return MEMORY_E メモリの割り当てに失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param status_type CertificatStatusRequest構造体にあるバイト型で、WOLFSSL_CSR2_OCSPまたはWOLFSSL_CSR2_OCSP_MULTIのいずれかである必要があります。
    \param options CertificateStatusRequestItemV2構造体に保持されるバイト型。

    _Example_
    \code
    WOLFSSL_CTX* ctx  = wolfSSL_CTX_new( protocol method );
    byte status_type;
    byte options;
    ...
    if(wolfSSL_CTX_UseOCSPStaplingV2(ctx, status_type, options); != SSL_SUCCESS){
    	// 失敗ケース
    }
    \endcode

    \sa TLSX_UseCertificateStatusRequestV2
    \sa wc_RNG_GenerateBlock
    \sa TLSX_Push
*/
int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief この関数は、'ssl'パラメータで渡されたSSLオブジェクトでSupported Elliptic Curves拡張の使用を有効にするために、クライアント側で呼び出されます。これは、wolfSSLクライアントによってClientHelloで有効化されたサポートされる曲線が送信されることを意味します。この関数は、複数の曲線を有効にするために複数回呼び出すことができます。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラー: sslがNULL、nameが不明な値(下記参照)。
    \return MEMORY_E メモリが不足している場合に返されるエラー。    \param ssl wolfSSL_new()で作成されたSSLオブジェクトへのポインタ。
    \param name セッションでサポートされる曲線を示します。利用可能なオプションは以下の通りです: enum { WOLFSSL_ECC_SECP160R1 = 0x10,
    WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15,
    WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18,
    WOLFSSL_ECC_SECP521R1 = 0x19 };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキストの作成に失敗しました。
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // sslの作成に失敗しました。
    }
    ret = wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // 楕円曲線拡張の使用に失敗しました。
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSupportedCurve
*/
int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name);

/*!
    \brief この関数は、ctxパラメータで渡されたSSLコンテキストから作成されたSSLオブジェクトに対して、サポートされる楕円曲線拡張の使用を有効にするためにクライアント側で呼び出されます。これは、有効にされたサポートされる曲線がwolfSSLクライアントによってClientHelloで送信されることを意味します。この関数は、複数の曲線を有効にするために複数回呼び出すことができます。

    \return SSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG 次のいずれかの場合に返されるエラー: ctxがNULL、nameが不明な値(下記参照)。
    \return MEMORY_E メモリが不足している場合に返されるエラー。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param name セッションでサポートされる曲線を示します。利用可能なオプションは以下の通りです: enum { WOLFSSL_ECC_SECP160R1 = 0x10,
    WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15,
    WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18,
    WOLFSSL_ECC_SECP521R1 = 0x19 };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // コンテキストの作成に失敗しました。
    }
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // 楕円曲線拡張の使用に失敗しました。
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSupportedCurve
*/
int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           word16 name);

/*!
    \ingroup IO

    \brief この関数は、提供されたWOLFSSL構造体に対して安全な再ネゴシエーションを強制します。これは推奨されません。

    \return SSL_SUCCESS 安全な再ネゴシエーションの設定に成功しました。
    \return BAD_FUNC_ARG sslがNULLの場合にエラーを返します。
    \return MEMORY_E 安全な再ネゴシエーション用のメモリを割り当てできない場合にエラーを返します。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // 何らかのwolfSSLメソッド
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS)
    {
        // 安全な再ネゴシエーションの設定エラー
    }
    \endcode

    \sa TLSX_Find
    \sa TLSX_UseSecureRenegotiation
*/
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数は安全な再ネゴシエーションハンドシェイクを実行します。wolfSSLはこの機能を推奨していないため、これはユーザが強制するものです。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合、またはサブルーチンで受け入れられない引数が渡された場合に返されます。
    \return SECURE_RENEGOTIATION_E ハンドシェイクの再ネゴシエーションでエラーがあった場合に返されます。
    \return SSL_FATAL_ERROR サーバまたはクライアント設定にエラーがあり、再ネゴシエーションを完了できなかった場合に返されます。wolfSSL_negotiate()を参照してください。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_Rehandshake(ssl) != SSL_SUCCESS){
	    // エラーが発生し、再ハンドシェイクは成功しませんでした。
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

    \brief 提供されたWOLFSSL構造体にセッションチケットを使用するよう強制します。定数HAVE_SESSION_TICKETが定義されており、定数NO_WOLFSSL_CLIENTが定義されていない必要があります。

    \return SSL_SUCCESS セッションチケットの使用設定に成功しました。
    \return BAD_FUNC_ARG sslがNULLの場合に返されます。
    \return MEMORY_E セッションチケット設定のためのメモリ割り当てエラー。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // 何らかのwolfSSLメソッド
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSessionTicket(ssl) != SSL_SUCCESS)
    {
        // セッションチケットの設定エラー
    }
    \endcode

    \sa TLSX_UseSessionTicket
*/
int wolfSSL_UseSessionTicket(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、wolfSSLコンテキストにセッションチケットを使用するよう設定します。

    \return SSL_SUCCESS 関数が正常に実行されました。
    \return BAD_FUNC_ARG ctxがNULLの場合に返されます。
    \return MEMORY_E 内部関数でメモリ割り当てエラー。

    \param ctx 使用するWOLFSSL_CTX構造体。

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL_METHOD method = // 何らかのwolfSSLメソッド ;
    ctx = wolfSSL_CTX_new(method);

    if(wolfSSL_CTX_UseSessionTicket(ctx) != SSL_SUCCESS)
    {
        // セッションチケットの設定エラー
    }
    \endcode

    \sa TLSX_UseSessionTicket
*/
int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief この関数は、Session構造体のticketメンバをバッファにコピーします。bufがNULLでbufSzが非NULLの場合、bufSzはチケット長に設定されます。

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG sslまたはbufSzがNULLの場合、またはbufSzが非NULLでbufがNULLの場合に返されます。


    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf メモリバッファを表すbyteポインタ。
    \param bufSz バッファサイズを表すword32ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buf;
    word32 bufSz;  // bufサイズで初期化
    …
    if(wolfSSL_get_SessionTicket(ssl, buf, bufSz) <= 0){
	    // バッファに何も書き込まれませんでした。
    } else {
	    // バッファはssl->session->ticketの内容を保持しています。
    }
    \endcode

    \sa wolfSSL_UseSessionTicket
    \sa wolfSSL_set_SessionTicket
*/
int wolfSSL_get_SessionTicket(WOLFSSL* ssl, unsigned char* buf, word32* bufSz);

/*!
    \ingroup IO

    \brief この関数は、WOLFSSL構造体内のWOLFSSL_SESSION構造体のticketメンバを設定します。関数に渡されたバッファはメモリにコピーされます。

    \return SSL_SUCCESS 関数の実行が成功した場合に返されます。関数はエラーなく返されました。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合に返されます。bufSz引数がゼロでないのにbuf引数がNULLの場合にも返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf セッション構造体のticketメンバに読み込まれるbyteポインタ。
    \param bufSz バッファのサイズを表すword32型。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buffer; // 読み込むファイル
    word32 bufSz;
    ...
    if(wolfSSL_KeepArrays(ssl, buffer, bufSz) != SSL_SUCCESS){
    	// バッファをメモリに読み込む際にエラーが発生しました。
    }
    \endcode

    \sa wolfSSL_set_SessionTicket_cb
*/
int wolfSSL_set_SessionTicket(WOLFSSL* ssl, const unsigned char* buf,
                              word32 bufSz);

/*!
    \brief この関数は、セッションチケットコールバックを設定します。CallbackSessionTicket型は、次のシグネチャを持つ関数ポインタです:
    int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*)

    \return SSL_SUCCESS 関数がエラーなく実行された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb CallbackSessionTicket型への関数ポインタ。
    \param ctx WOLFSSL構造体のsession_ticket_ctxメンバへのvoidポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int sessionTicketCB(WOLFSSL* ssl, const unsigned char* ticket, int ticketSz,
				void* ctx){ … }
    wolfSSL_set_SessionTicket_cb(ssl, sessionTicketCB, (void*)"initial session");
    \endcode

    \sa wolfSSL_get_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
*/
int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                 CallbackSessionTicket cb, void* ctx);

/*!
    \brief この関数は、TLS v1.3ハンドシェイクが確立された後、クライアントにセッションチケットを送信します。

    \return WOLFSSL_SUCCESS 新しいセッションチケットが送信された場合に返されます。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULL、またはTLS v1.3を使用していない場合に返されます。
    \return SIDE_ERROR サーバでない場合に返されます。
    \return NOT_READY_ERROR ハンドシェイクが完了していない場合に返されます。
    \return WOLFSSL_FATAL_ERROR メッセージの作成または送信に失敗した場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    ret = wolfSSL_send_SessionTicket(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // 新しいセッションチケットが送信されませんでした。
    }
    \endcode

    \sa wolfSSL_get_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
 */
int wolfSSL_send_SessionTicket(WOLFSSL* ssl);

/*!
    \brief この関数は、RFC 5077で規定されているセッションチケットをサポートするサーバのセッションチケット鍵暗号化コールバック関数を設定します。

    \return SSL_SUCCESS セッションの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 失敗時に返されます。これは、関数に無効な引数が渡された場合に発生します。

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTXオブジェクトへのポインタ。
    \param cb セッションチケットを暗号化/復号するユーザコールバック関数
    \param ssl(Callback) wolfSSL_new()で作成されたWOLFSSLオブジェクトへのポインタ
    \param key_name(Callback) このチケットコンテキスト用の一意の鍵名、ランダムに生成されるべきです
    \param iv(Callback) このチケット用の一意のIV、最大128ビット、ランダムに生成されるべきです
    \param mac(Callback) このチケット用の最大256ビットのmac
    \param enc(Callback) この暗号化パラメータがtrueの場合、ユーザはkey_name、iv、macを入力し、長さinLenのチケットをインプレースで暗号化し、結果の出力長を*outLenに設定する必要があります。WOLFSSL_TICKET_RET_OKを返すことで、wolfSSLに暗号化が成功したことを伝えます。この暗号化パラメータがfalseの場合、ユーザはkey_name、iv、macを使用して長さinLenのチケットのインプレース復号を実行する必要があります。結果の復号長は*outLenに設定する必要があります。WOLFSSL_TICKET_RET_OKを返すことで、wolfSSLに復号されたチケットを使用して続行するよう伝えます。WOLFSSL_TICKET_RET_CREATEを返すことで、wolfSSLに復号されたチケットを使用するが、クライアントに送信する新しいチケットも生成するよう伝えます。これは最近鍵をロールした場合に完全なハンドシェイクを強制したくない場合に役立ちます。WOLFSSL_TICKET_RET_REJECTを返すことで、wolfSSLにこのチケットを拒否し、完全なハンドシェイクを実行し、通常のセッション再開用の新しい標準セッションIDを作成するよう伝えます。WOLFSSL_TICKET_RET_FATALを返すことで、wolfSSLに致命的エラーで接続試行を終了するよう伝えます。
    \param ticket(Callback) 暗号化されたチケットの入出力バッファ。encパラメータを参照してください。
    \param inLen(Callback) ticketパラメータの入力長。
    \param outLen(Callback) ticketパラメータの結果出力長。コールバックに入るとき、outLenはticketバッファで利用可能な最大サイズを示します。
    \param userCtx(Callback) wolfSSL_CTX_set_TicketEncCtx()で設定されたユーザコンテキスト

    _Example_
    \code
    wolfssl/test.hのmyTicketEncCb()を参照してください。
    サンプルサーバとサンプルechoserverで使用されています。
    \endcode

    \sa wolfSSL_CTX_set_TicketHint
    \sa wolfSSL_CTX_set_TicketEncCtx
*/
int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb);

/*!
    \brief この関数は、クライアントに中継されるセッションチケットヒントを設定します。サーバ側での使用。

    \return SSL_SUCCESS セッションの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 失敗時に返されます。これは、関数に無効な引数が渡された場合に発生します。

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTXオブジェクトへのポインタ。
    \param hint チケットが有効である可能性がある秒数。クライアントへのヒント。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCb*/
int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int);

/*!
    \brief この関数は、コールバック用のセッションチケット暗号化ユーザコンテキストを設定します。サーバ側で使用します。

    \return SSL_SUCCESS セッションの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 失敗時に返されます。これは関数に無効な引数が渡されたことが原因です。

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTXオブジェクトへのポインタ。
    \param userCtx コールバック用のユーザコンテキスト。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCb
*/
int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void*);

/*!
    \brief この関数は、コールバック用のセッションチケット暗号化ユーザコンテキストを取得します。サーバ側で使用します。

    \return userCtx セッションの取得に成功した場合に返されます。
    \return NULL 失敗時に返されます。これは関数に無効な引数が渡された場合、またはユーザコンテキストが設定されていない場合に発生します。

    \param ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTXオブジェクトへのポインタ。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCtx
*/
void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx);

/*!
    \brief この関数は、ハンドシェイク完了コールバックを設定します。WOLFSSL構造体のhsDoneCbとhsDoneCtxメンバがこの関数で設定されます。

    \return SSL_SUCCESS 関数がエラーなしで実行された場合に返されます。WOLFSSL構造体のhsDoneCbとhsDoneCtxメンバが設定されます。
    \return BAD_FUNC_ARG WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb HandShakeDoneCb型の関数ポインタで、次の形式のシグネチャを持ちます: int (*HandShakeDoneCb)(WOLFSSL*, void*);
    \param user_ctx ユーザ登録コンテキストへのvoidポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int myHsDoneCb(WOLFSSL* ssl, void* user_ctx){
        // コールバック関数
    }
    …
    wolfSSL_SetHsDoneCb(ssl, myHsDoneCb, NULL);
    \endcode

    \sa HandShakeDoneCb
*/
int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx);

/*!
    \ingroup IO

    \brief この関数は、セッションの統計情報を出力します。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなしで返された場合に返されます。セッション統計が正常に取得され、出力されました。
    \return BAD_FUNC_ARG サブルーチンwolfSSL_get_session_stats()に許容できない引数が渡された場合に返されます。
    \return BAD_MUTEX_E サブルーチンでmutexエラーが発生した場合に返されます。

    \param none パラメータなし。

    _Example_
    \code
    // 統計を取得するためのセッションオブジェクトが必要です
    if(wolfSSL_PrintSessionStats(void) != SSL_SUCCESS){
        // セッション統計を出力しませんでした
    }

    \endcode

    \sa wolfSSL_get_session_stats
*/
int wolfSSL_PrintSessionStats(void);

/*!
    \ingroup IO

    \brief この関数は、セッションの統計情報を取得します。

    \return SSL_SUCCESS 関数とサブルーチンがエラーなしで返された場合に返されます。セッション統計が正常に取得され、出力されました。
    \return BAD_FUNC_ARG サブルーチンwolfSSL_get_session_stats()に許容できない引数が渡された場合に返されます。
    \return BAD_MUTEX_E サブルーチンでmutexエラーが発生した場合に返されます。

    \param active 総現在セッション数を表すword32ポインタ。
    \param total 総セッション数を表すword32ポインタ。
    \param peak ピークセッション数を表すword32ポインタ。
    \param maxSessions 最大セッション数を表すword32ポインタ。

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

    \brief この関数は、crとsrの値をコピーし、wc_PRF(疑似乱数関数)に渡し、その値を返します。

    \return 0 成功時。
    \return BUFFER_E バッファのサイズでエラーが発生する場合に返されます。
    \return MEMORY_E サブルーチンが動的メモリの割り当てに失敗した場合に返されます。

    \param ms Arrays構造体に保持されているマスターシークレット。
    \param msLen マスターシークレットの長さ。
    \param pms Arrays構造体に保持されているプリマスターシークレット。
    \param pmsLen プリマスターシークレットの長さ。
    \param cr クライアントランダム。
    \param sr サーバランダム。
    \param tls1_2 バージョンが少なくともTLSバージョン1.2であることを示します。
    \param hash_type ハッシュタイプを示します。

    _Example_
    \code
    WOLFSSL* ssl;

    MakeTlsMasterSecretで呼び出され、以下のように必要な情報を取得します:

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

    \brief TLS鍵を導出するための外部向けラッパー。

    \return 0 成功時に返されます。
    \return BUFFER_E labLenとseedLenの合計(合計サイズを計算)が最大サイズを超えた場合に返されます。
    \return MEMORY_E メモリの割り当てに失敗した場合に返されます。

    \param key_data DeriveTlsKeysで割り当てられ、最終ハッシュを保持するためにwc_PRFに渡されるバイトポインタ。
    \param keyLen DeriveTlsKeysでWOLFSSL構造体のspecsメンバから導出されるword32型。
    \param ms WOLFSSL構造体内のarrays構造体に保持されているマスターシークレットを保持する定数ポインタ型。
    \param msLen 列挙定義SECRET_LENでマスターシークレットの長さを保持するword32型。
    \param sr WOLFSSL構造体内のarrays構造体のserverRandomメンバへの定数バイトポインタ。
    \param cr WOLFSSL構造体内のarrays構造体のclientRandomメンバへの定数バイトポインタ。
    \param tls1_2 IsAtLeastTLSv1_2()から返される整数型。
    \param hash_type WOLFSSL構造体に保持されている整数型。

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
    \brief wolfSSL_connect_ex()は、HandShakeコールバックを設定できる拡張です。これは、デバッガが利用できず、スニッフィングが実用的でない場合に、組み込みシステムのデバッグサポートに役立ちます。HandShakeコールバックは、ハンドシェイクエラーが発生したかどうかに関わらず呼び出されます。SSLパケットの最大数が既知であるため、動的メモリは使用されません。パケット名はpacketNames[]を通じてアクセスできます。接続拡張はまた、タイムアウト値と共にTimeoutコールバックを設定できます。これは、ユーザがTCPスタックのタイムアウトを待ちたくない場合に便利です。この拡張は、いずれか、両方、またはどちらのコールバックもなしで呼び出すことができます。

    \return SSL_SUCCESS 成功時。
    \return GETTIME_ERROR gettimeofday()がエラーに遭遇した場合に返されます。
    \return SETITIMER_ERROR setitimer()がエラーに遭遇した場合に返されます。
    \return SIGACT_ERROR sigaction()がエラーに遭遇した場合に返されます。
    \return SSL_FATAL_ERROR 基礎となるSSL_connect()呼び出しがエラーに遭遇した場合に返されます。

    \param none パラメータなし。

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_accept_ex
*/
int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                       TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

/*!
    \brief wolfSSL_accept_ex()は、HandShakeコールバックを設定できる拡張です。これは、デバッガが利用できず、スニッフィングが実用的でない場合に、組み込みシステムのデバッグサポートに役立ちます。HandShakeコールバックは、ハンドシェイクエラーが発生したかどうかに関わらず呼び出されます。SSLパケットの最大数が既知であるため、動的メモリは使用されません。パケット名はpacketNames[]を通じてアクセスできます。接続拡張はまた、タイムアウト値と共にTimeoutコールバックを設定できます。これは、ユーザがTCPスタックのタイムアウトを待ちたくない場合に便利です。この拡張は、いずれか、両方、またはどちらのコールバックもなしで呼び出すことができます。

    \return SSL_SUCCESS 成功時。
    \return GETTIME_ERROR gettimeofday()がエラーに遭遇した場合に返されます。
    \return SETITIMER_ERROR setitimer()がエラーに遭遇した場合に返されます。
    \return SIGACT_ERROR sigaction()がエラーに遭遇した場合に返されます。
    \return SSL_FATAL_ERROR 基礎となるSSL_accept()呼び出しがエラーに遭遇した場合に返されます。

    \param none パラメータなし。

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

    \brief これは、BIOの内部ファイルポインタを設定するために使用されます。

    \return SSL_SUCCESS ファイルポインタの設定に成功した場合。
    \return SSL_FAILURE エラーケースが発生した場合。

    \param bio ペアを設定するWOLFSSL_BIO構造体。
    \param fp bioに設定するファイルポインタ。
    \param c ファイルクローズ動作フラグ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, fp, BIO_CLOSE);
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_get_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c);

/*!
    \ingroup IO

    \brief これは、BIOの内部ファイルポインタを取得するために使用されます。

    \return SSL_SUCCESS ファイルポインタの取得に成功した場合。
    \return SSL_FAILURE エラーケースが発生した場合。

    \param bio ペアを設定するWOLFSSL_BIO構造体。
    \param fp bioに設定するファイルポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_get_fp(bio, &fp);
    // ret値を確認
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp);

/*!
    \ingroup Setup

    \brief この関数は、秘密鍵が使用されている証明書と一致していることを確認します。

    \return SSL_SUCCESS 一致に成功した場合。
    \return SSL_FAILURE エラーケースが発生した場合。
    \return <0 SSL_FAILURE以外のすべてのエラーケースは負の値です。

    \param ssl 確認するWOLFSSL構造体。

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // sslを作成してセットアップ
    ret  = wolfSSL_check_private_key(ssl);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_check_private_key(const WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief この関数は、渡されたNID値に一致する拡張インデックスを検索して返します。

    \return ＞= 0 成功時、拡張インデックスが返されます。
    \return -1 拡張が見つからない場合、またはエラーが発生した場合。

    \param x509 拡張を検索するために解析する証明書。
    \param nid 見つける拡張OID。
    \param lastPos lastPos以降の拡張から検索を開始します。
                   最初は-1に設定します。

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int lastPos = -1;
    int idx;

    idx = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints, lastPos);
    \endcode*/
int wolfSSL_X509_get_ext_by_NID(const WOLFSSL_X509* x509,
                                             int nid, int lastPos);

/*!
    \ingroup CertsKeys

    \brief この関数は渡されたNID値に一致する拡張を検索して返します。

    \return pointer 成功した場合、STACK_OF(WOLFSSL_ASN1_OBJECT)ポインタが返されます。
    \return NULL 拡張が見つからない、またはエラーが発生した場合。

    \param x509 拡張を解析する証明書。
    \param nid 検索する拡張OID。
    \param c NULLでない場合、複数の拡張が見つかった場合は-2、見つからなかった場合は-1、見つかってクリティカルでない場合は0、見つかってクリティカルな場合は1に設定されます。
    \param idx NULLの場合は最初に一致した拡張を返します。それ以外の場合、x509に格納されていなければidxから開始します。

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int c;
    int idx = 0;
    STACK_OF(WOLFSSL_ASN1_OBJECT)* sk;

    sk = wolfSSL_X509_get_ext_d2i(x509, NID_basic_constraints, &c, &idx);
    // skがNULLでないか確認してから使用。使用後はskを解放する必要があります
    \endcode

    \sa wolfSSL_sk_ASN1_OBJECT_free
*/
void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509,
                                                     int nid, int* c, int* idx);

/*!
    \ingroup CertsKeys

    \brief この関数はDER証明書のハッシュを返します。

    \return SSL_SUCCESS ハッシュの作成に成功した場合。
    \return SSL_FAILURE 不正な入力またはハッシュ失敗時に返されます。

    \param x509 ハッシュを取得する証明書。
    \param digest 使用するハッシュアルゴリズム。
    \param buf ハッシュを保持するバッファ。
    \param len バッファの長さ。

    _Example_
    \code
    WOLFSSL_X509* x509;
    unsigned char buffer[64];
    unsigned int bufferSz;
    int ret;

    ret = wolfSSL_X509_digest(x509, wolfSSL_EVP_sha256(), buffer, &bufferSz);
    // ret値を確認
    \endcode

    \sa none
*/
int wolfSSL_X509_digest(const WOLFSSL_X509* x509,
        const WOLFSSL_EVP_MD* digest, unsigned char* buf, unsigned int* len);

/*!
    \ingroup Setup

    \brief ハンドシェイク中に使用するWOLFSSL構造体の証明書を設定するために使用されます。

    \return SSL_SUCCESS 引数の設定に成功した場合。
    \return SSL_FAILURE NULL引数が渡された場合。

    \param ssl 証明書を設定するWOLFSSL構造体。
    \param x509 使用する証明書。

    _Example_
    \code WOLFSSL* ssl;
    WOLFSSL_X509* x509
    int ret;
    // sslオブジェクトとx509を作成
    ret  = wolfSSL_use_certificate(ssl, x509);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief ハンドシェイク中に使用するWOLFSSL構造体の証明書を設定するために使用されます。DER形式のバッファが必要です。

    \return SSL_SUCCESS 引数の設定に成功した場合。
    \return SSL_FAILURE NULL引数が渡された場合。

    \param ssl 証明書を設定するWOLFSSL構造体。
    \param der 使用するDER証明書。
    \param derSz 渡されたDERバッファのサイズ。

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* der;
    int derSz;
    int ret;
    // sslオブジェクトを作成してDER変数を設定
    ret  = wolfSSL_use_certificate_ASN1(ssl, der, derSz);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                     int derSz);

/*!
    \ingroup CertsKeys

    \brief WOLFSSL構造体の秘密鍵を設定するために使用されます。

    \return SSL_SUCCESS 引数の設定に成功した場合。
    \return SSL_FAILURE NULLのsslが渡された場合。すべてのエラーケースは負の値になります。

    \param ssl 引数を設定するWOLFSSL構造体。
    \param pkey 使用する秘密鍵。

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_EVP_PKEY* pkey;
    int ret;
    // sslオブジェクトを作成して秘密鍵をセットアップ
    ret  = wolfSSL_use_PrivateKey(ssl, pkey);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_PrivateKey(WOLFSSL* ssl, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief WOLFSSL構造体の秘密鍵を設定するために使用されます。DER形式の鍵バッファが必要です。

    \return SSL_SUCCESS 秘密鍵の解析と設定に成功した場合。
    \return SSL_FAILURE NULLのsslが渡された場合。すべてのエラーケースは負の値になります。

    \param pri 秘密鍵のタイプ。
    \param ssl 引数を設定するWOLFSSL構造体。
    \param der DER鍵を保持するバッファ。
    \param derSz derバッファのサイズ。

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // sslオブジェクトを作成して秘密鍵をセットアップ
    ret  = wolfSSL_use_PrivateKey_ASN1(1, ssl, pkey, pkeySz);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_PrivateKey_ASN1(int pri, WOLFSSL* ssl,
                                            unsigned char* der, long derSz);

/*!
    \ingroup CertsKeys

    \brief WOLFSSL構造体の秘密鍵を設定するために使用されます。DER形式のRSA鍵バッファが必要です。

    \return SSL_SUCCESS 秘密鍵の解析と設定に成功した場合。
    \return SSL_FAILURE NULLのsslが渡された場合。すべてのエラーケースは負の値になります。

    \param ssl 引数を設定するWOLFSSL構造体。
    \param der DER鍵を保持するバッファ。
    \param derSz derバッファのサイズ。

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // sslオブジェクトを作成してRSA秘密鍵をセットアップ
    ret  = wolfSSL_use_RSAPrivateKey_ASN1(ssl, pkey, pkeySz);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_RSAPrivateKey_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                long derSz);

/*!
    \ingroup CertsKeys

    \brief この関数はdsaのパラメータを新しく作成されたWOLFSSL_DH構造体に複製します。

    \return WOLFSSL_DH 複製に成功した場合、WOLFSSL_DH構造体を返します。
    \return NULL 失敗時。

    \param dsa 複製するWOLFSSL_DSA構造体。

    _Example_
    \code
    WOLFSSL_DH* dh;
    WOLFSSL_DSA* dsa;
    // dsaをセットアップ
    dh = wolfSSL_DSA_dup_DH(dsa);

    // dhがnullでないか確認
    \endcode

    \sa none
*/
WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *r);

/*!
    \ingroup Setup

    \brief ハンドシェイク完了後にマスターキーを取得するために使用されます。

    \return ＞0 データの取得に成功した場合、0より大きい値を返します。
    \return 0 ランダムデータバッファがない、またはエラー状態の場合は0を返します。
    \return max 渡されたoutSzが0の場合、必要な最大バッファサイズが返されます。

    \param ses マスターシークレットバッファを取得するWOLFSSL_SESSION構造体。
    \param out データを保持するバッファ。
    \param outSz 渡されたoutバッファのサイズ(0の場合、関数は必要な最大バッファサイズを返します)。

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // ハンドシェイクを完了してセッション構造体を取得
    bufferSz  = wolfSSL_SESSION_get_master_secret(ses, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_SESSION_get_master_secret(ses, buffer, bufferSz);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key(const WOLFSSL_SESSION* ses,
        unsigned char* out, int outSz);

/*!
    \ingroup Setup

    \brief マスターシークレットキーの長さを取得するために使用されます。

    \return size マスターシークレットキーのサイズを返します。

    \param ses マスターシークレットバッファを取得するWOLFSSL_SESSION構造体。

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // ハンドシェイクを完了してセッション構造体を取得
    bufferSz  = wolfSSL_SESSION_get_master_secret_length(ses);
    buffer = malloc(bufferSz);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key_length(const WOLFSSL_SESSION* ses);

/*!
    \ingroup Setup

    \brief ctxのWOLFSSL_X509_STORE構造体のsetter関数です。

    \return none 戻り値なし。

    \param ctx 証明書ストアポインタを設定するWOLFSSL_CTX構造体へのポインタ。
    \param str ctxに設定するWOLFSSL_X509_STOREへのポインタ。

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // ctxとstをセットアップ
    st = wolfSSL_CTX_set_cert_store(ctx, st);
    // stを使用
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);

/*!
    \ingroup CertsKeys

    \brief この関数はbioからDERバッファを取得し、それをWOLFSSL_X509構造体に変換します。

    \return pointer 成功時にWOLFSSL_X509構造体ポインタを返します。
    \return Null 失敗時にNULLを返します。

    \param bio DER証明書バッファを持つWOLFSSL_BIO構造体へのポインタ。
    \param x509 作成された新しいWOLFSSL_X509構造体に設定されるポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // DERをbioにロード
    x509 = wolfSSL_d2i_X509_bio(bio, NULL);
    // または
    wolfSSL_d2i_X509_bio(bio, &x509);
    // 返されたx509を使用(NULLをチェック)
    \endcode

    \sa none
*/
WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509** x509);

/*!
    \ingroup Setup

    \brief ctxのWOLFSSL_X509_STORE構造体のgetter関数です。

    \return WOLFSSL_X509_STORE* ポインタの取得に成功した場合。
    \return NULL NULL引数が渡された場合に返されます。

    \param ctx 証明書ストアポインタを取得するWOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // ctxをセットアップ
    st = wolfSSL_CTX_get_cert_store(ctx);
    // stを使用
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_cert_store
*/
WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief 読み取り保留中のバイト数を取得します。BIOタイプがBIO_BIOの場合、ペアから読み取るバイト数です。BIOがSSLオブジェクトを含む場合、SSLオブジェクトからの保留中のデータです(wolfSSL_pending(ssl))。BIO_MEMORYタイプの場合、メモリバッファのサイズを返します。

    \return ＞=0 保留中のバイト数。

    \param bio すでに作成されているWOLFSSL_BIO構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_BIO* bio;    int pending;
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

    \brief ハンドシェイク中にサーバーから送信されたランダムデータを取得するために使用されます。

    \return ＞0 データの取得に成功した場合、0より大きい値を返します。
    \return 0 ランダムデータバッファがない場合、またはエラー状態の場合、0を返します。
    \return max 渡されたoutSzが0の場合、必要な最大バッファサイズを返します。

    \param ssl クライアントのランダムデータバッファを取得するWOLFSSL構造体。
    \param out ランダムデータを保持するバッファ。
    \param outSz 渡されたoutバッファのサイズ(0の場合、関数は必要な最大バッファサイズを返します)。

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_server_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_server_random(ssl, buffer, bufferSz);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_server_random(const WOLFSSL *ssl,
                                             unsigned char *out, size_t outlen);

/*!
    \ingroup Setup

    \brief ハンドシェイク中にクライアントから送信されたランダムデータを取得するために使用されます。

    \return ＞0 データの取得に成功した場合、0より大きい値を返します。
    \return 0 ランダムデータバッファがない場合、またはエラー状態の場合、0を返します。
    \return max 渡されたoutSzが0の場合、必要な最大バッファサイズを返します。

    \param ssl クライアントのランダムデータバッファを取得するWOLFSSL構造体。
    \param out ランダムデータを保持するバッファ。
    \param outSz 渡されたoutバッファのサイズ(0の場合、関数は必要な最大バッファサイズを返します)。

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_client_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_client_random(ssl, buffer, bufferSz);
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_client_random(const WOLFSSL* ssl,
                                              unsigned char* out, size_t outSz);

/*!
    \ingroup Setup

    \brief ctx内に設定されたパスワードコールバックのgetter関数です。

    \return func 成功時にはコールバック関数を返します。
    \return NULL ctxがNULLの場合、NULLを返します。

    \param ctx コールバックを取得するWOLFSSL_CTX構造体。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    wc_pem_password_cb cb;
    // ctxをセットアップ
    cb = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //cbを使用
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX*
                                                                  ctx);

/*!
    \ingroup Setup

    \brief ctx内に設定されたパスワードコールバックユーザーデータのgetter関数です。

    \return pointer 成功時にはユーザーデータポインタを返します。
    \return NULL ctxがNULLの場合、NULLを返します。

    \param ctx ユーザーデータを取得するWOLFSSL_CTX構造体。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    // ctxをセットアップ
    data = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //dataを使用
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void *wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx);

/*!
    \ingroup CertsKeys

    \brief この関数はwolfSSL_PEM_read_bio_X509と同じように動作します。AUXは、信頼された/拒否されたユースケースや人間が読みやすいフレンドリ名などの追加情報を含むことを意味します。

    \return WOLFSSL_X509 PEMバッファの解析に成功した場合、WOLFSSL_X509構造体が返されます。
    \return Null PEMバッファの解析に失敗した場合。

    \param bp PEMバッファを取得するWOLFSSL_BIO構造体。
    \param x 関数の副作用によってWOLFSSL_X509を設定する場合。
    \param cb パスワードコールバック。
    \param u NULL終端のユーザーパスワード。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // bioをセットアップ
    X509 = wolfSSL_PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    //x509がnullでないことを確認してから使用
    \endcode

    \sa wolfSSL_PEM_read_bio_X509
*/
WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_AUX
        (WOLFSSL_BIO *bp, WOLFSSL_X509 **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup CertsKeys

    \brief WOLFSSL_CTX構造体のdhメンバをDiffie-Hellmanパラメータで初期化します。

    \return SSL_SUCCESS 関数が正常に実行された場合に返されます。
    \return BAD_FUNC_ARG ctxまたはdh構造体がNULLの場合に返されます。
    \return SSL_FATAL_ERROR 構造体の値の設定にエラーがあった場合に返されます。
    \return MEMORY_E メモリの割り当てに失敗した場合に返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param dh WOLFSSL_DH構造体へのポインタ。

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

    \brief この関数は、bio内のPEMバッファからDSAパラメータを取得します。

    \return WOLFSSL_DSA PEMバッファの解析に成功した場合、WOLFSSL_DSA構造体が作成されて返されます。
    \return Null PEMバッファの解析に失敗した場合。

    \param bio PEMメモリポインタを取得するためのWOLFSSL_BIO構造体へのポインタ。
    \param x 新しいWOLFSSL_DSA構造体に設定されるポインタ。
    \param cb パスワードコールバック関数。
    \param u null終端のパスワード文字列。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_DSA* dsa;
    // bioをセットアップ
    dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL);

    // dsaがNULLでないことを確認してからdsaを使用
    \endcode

    \sa none
*/
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp,
    WOLFSSL_DSA **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup Debug

    \brief この関数は、WOLFSSL_ERRORから発生した最後のエラーの絶対値を返します。

    \return error 最後のエラーの絶対値を返します。

    \param none パラメータはありません。

    _Example_
    \code
    unsigned long err;
    ...
    err = wolfSSL_ERR_peek_last_error();
    // err値を検査
    \endcode

    \sa wolfSSL_ERR_print_errors_fp
*/
unsigned long wolfSSL_ERR_peek_last_error(void);

/*!
    \ingroup CertsKeys

    \brief この関数は、ピアの証明書チェーンを取得します。

    \return pointer ピアのCertificateスタックへのポインタを返します。
    \return NULL ピア証明書がない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    wolfSSL_connect(ssl);
    STACK_OF(WOLFSSL_X509)* chain = wolfSSL_get_peer_cert_chain(ssl);
    if(chain){
	    // ピア証明書チェーンへのポインタがあります
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL*);

/*!
    \ingroup Setup

    \brief この関数は、WOLFSSL_CTXオブジェクトのオプションビットをリセットします。

    \return option 新しいオプションビット。

    \param ctx SSLコンテキストへのポインタ。

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

    \brief この関数は、WOLFSSL構造体のjObjectRefメンバを設定します。

    \return SSL_SUCCESS jObjectRefがobjPtrに適切に設定された場合に返されます。
    \return SSL_FAILURE 関数が適切に実行されず、jObjectRefが設定されていない場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param objPtr jObjectRefに設定されるvoidポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new();
    void* objPtr = &obj;
    ...
    if(wolfSSL_set_jobject(ssl, objPtr)){
    	// 成功ケース
    }
    \endcode

    \sa wolfSSL_get_jobject
*/
int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr);

/*!
    \ingroup IO

    \brief この関数は、WOLFSSL構造体のjObjectRefメンバを返します。

    \return value WOLFSSL構造体がNULLでない場合、関数はjObjectRef値を返します。
    \return NULL WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL(ctx);
    ...
    void* jobject = wolfSSL_get_jobject(ssl);

    if(jobject != NULL){
    	// 成功ケース
    }
    \endcode

    \sa wolfSSL_set_jobject
*/
void* wolfSSL_get_jobject(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、ssl内にコールバックを設定します。コールバックはハンドシェイクメッセージを監視するためのものです。cbのNULL値はコールバックをリセットします。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE NULLのsslが渡された場合。

    \param ssl コールバック引数を設定するWOLFSSL構造体。

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // retを確認
    \endcode

    \sa wolfSSL_set_msg_callback_arg
*/
int wolfSSL_set_msg_callback(WOLFSSL *ssl, SSL_Msg_Cb cb);

/*!
    \ingroup Setup

    \brief この関数は、ssl内に関連するコールバックコンテキスト値を設定します。値はコールバック引数に渡されます。

    \return none 戻り値はありません。

    \param ssl コールバック引数を設定するWOLFSSL構造体。

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // retを確認
    wolfSSL_set_msg_callback(ssl, arg);
    \endcode

    \sa wolfSSL_set_msg_callback
*/
int wolfSSL_set_msg_callback_arg(WOLFSSL *ssl, void* arg);

/*!
    \ingroup CertsKeys

    \brief この関数は、ピア証明書から次の代替名(もしあれば)を返します。

    \return NULL 次の代替名がない場合。
    \return cert->altNamesNext->name WOLFSSL_X509構造体から返されます。    altNameリストからの文字列値が存在する場合に返されます。

    \param cert wolfSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
                                                        DYNAMIC_TYPE_X509);
    …
    int x509NextAltName = wolfSSL_X509_get_next_altname(x509);
    if(x509NextAltName == NULL){
        //別のalt nameはありません。
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
char* wolfSSL_X509_get_next_altname(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief この関数は、x509がNULLかどうかを確認し、NULLでない場合はx509構造体のnotBeforeメンバを返します。

    \return pointer x509構造体のnotBeforeメンバへのASN1_TIMEを持つ構造体へのポインタ。
    \return NULL x509構造体がNULLの場合、関数はNULLを返します。

    \param x509 WOLFSSL_X509構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    …
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notBefore(x509);
    if(notAfter == NULL){
        //x509オブジェクトがNULLでした。
    }
    \endcode

    \sa wolfSSL_X509_get_notAfter
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(WOLFSSL_X509*);

/*!
    \ingroup IO

    \brief この関数はクライアント側で呼び出され、サーバとのSSL/TLSハンドシェイクを開始します。この関数が呼び出されるとき、基礎となる通信チャネルはすでに設定されています。wolfSSL_connect()は、ブロッキングI/Oと非ブロッキングI/Oの両方で動作します。基礎となるI/Oが非ブロッキングの場合、wolfSSL_connect()は、基礎となるI/OがwolfSSL_connect()がハンドシェイクを続行するために必要とするものを満たすことができないときに返されます。この場合、wolfSSL_get_error()の呼び出しはSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEを返します。呼び出しプロセスは、基礎となるI/Oの準備ができたときにwolfSSL_connect()の呼び出しを繰り返す必要があり、wolfSSLは中断したところから再開します。非ブロッキングソケットを使用する場合、何もする必要はありませんが、select()を使用して必要な条件を確認できます。基礎となるI/Oがブロッキングの場合、wolfSSL_connect()はハンドシェイクが完了するかエラーが発生するまで返されません。wolfSSLは、OpenSSLとは異なるアプローチで証明書検証を行います。クライアントのデフォルトポリシーはサーバを検証することです。つまり、サーバを検証するためのCAを読み込まない場合、接続エラー、検証不可(-155)が発生します。サーバの検証が失敗してもSSL_connectが成功し、セキュリティを低下させるOpenSSLの動作を模倣したい場合は、SSL_new()を呼び出す前にSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);を呼び出すことでこれを実現できます。ただし、推奨されません。

    \return SSL_SUCCESS 成功した場合。
    \return SSL_FATAL_ERROR エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出してください。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

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
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_accept
*/
int  wolfSSL_connect(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、HelloRetryRequestメッセージにCookieを含める必要があることを示すために、サーバ側で呼び出されます。また、プロトコルDTLS v1.3を使用する場合、ハンドシェイクには常にCookie交換が含まれることを示します。プロトコルDTLS v1.3を使用する場合、Cookie交換はデフォルトで有効になっていることに注意してください。Cookieは現在のトランスクリプトのハッシュを保持しており、別のサーバプロセスが応答のClientHelloを処理できるようにします。secretは、Cookieデータの完全性チェックを生成する際に使用されます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] secret secretを保持するバッファへのポインタ。NULLを渡すと、新しいランダムなsecretを生成することを示します。
    \param [in] secretSz secretのサイズ(バイト単位)。0を渡すと、デフォルトサイズを使用することを示します:WC_SHA256_DIGEST_SIZE(SHA-256が利用できない場合はWC_SHA_DIGEST_SIZE)。

    \return BAD_FUNC_ARG sslがNULLまたはTLS v1.3を使用していない場合。
    \return SIDE_ERROR クライアントで呼び出された場合。
    \return WOLFSSL_SUCCESS 成功した場合。
    \return MEMORY_ERROR secretを保存するための動的メモリの割り当てに失敗した場合。
    \return Another 内部エラーの場合は他の負の値。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    char secret[32];
    ...
    ret = wolfSSL__send_hrr_cookie(ssl, secret, sizeof(secret));
    if (ret != WOLFSSL_SUCCESS) {
        // Cookieとsecretの使用設定に失敗しました。
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_disable_hrr_cookie
*/
int  wolfSSL_send_hrr_cookie(WOLFSSL* ssl,
    const unsigned char* secret, unsigned int secretSz);

/*!

    \ingroup Setup

    \brief この関数は、HelloRetryRequestメッセージにCookieを含めてはならないこと、およびプロトコルDTLS v1.3を使用している場合、ハンドシェイクにCookie交換を含めないことを示すために、サーバ側で呼び出されます。プロトコルDTLS v1.3を使用する際にCookie交換を行わないと、サーバがDoS/増幅攻撃に対して脆弱になる可能性があることに注意してください。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return WOLFSSL_SUCCESS 成功した場合。
    \return BAD_FUNC_ARG sslがNULLまたはTLS v1.3を使用していない場合。
    \return SIDE_ERROR クライアントで呼び出された場合。

    \sa wolfSSL_send_hrr_cookie
*/
int wolfSSL_disable_hrr_cookie(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、ハンドシェイクが完了した後、再開セッションチケットの送信を停止するために、サーバで呼び出されます。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    \return BAD_FUNC_ARG ctxがNULLまたはTLS v1.3を使用していない場合。
    \return SIDE_ERROR クライアントで呼び出された場合。
    \return 0 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_ticket_TLSv13(ctx);
    if (ret != 0) {
        // no ticketの設定に失敗しました。
    }
    \endcode

    \sa wolfSSL_no_ticket_TLSv13
*/
int  wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief この関数は、ハンドシェイクが完了した後、再開セッションチケットの送信を停止するために、サーバで呼び出されます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return BAD_FUNC_ARG sslがNULLまたはTLS v1.3を使用していない場合。
    \return SIDE_ERROR クライアントで呼び出された場合。
    \return 0 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_ticket_TLSv13(ssl);
    if (ret != 0) {
        // no ticketの設定に失敗しました。
    }
    \endcode

    \sa wolfSSL_CTX_no_ticket_TLSv13
*/
int  wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、事前共有鍵を認証に使用するハンドシェイクの際に、Diffie-Hellman(DH)スタイルの鍵交換を禁止するために、TLS v1.3 wolfSSLコンテキストで呼び出されます。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    \return BAD_FUNC_ARG ctxがNULLまたはTLS v1.3を使用していない場合。
    \return 0 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_dhe_psk(ctx);
    if (ret != 0) {
        // PSKハンドシェイクのDHE無効化の設定に失敗しました。
    }
    \endcode

    \sa wolfSSL_no_dhe_psk
*/
int  wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief この関数は、事前共有鍵を認証に使用するハンドシェイクの際に、Diffie-Hellman(DH)スタイルの鍵交換を禁止するために、TLS v1.3クライアントまたはサーバwolfSSLで呼び出されます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return BAD_FUNC_ARG sslがNULLまたはTLS v1.3を使用していない場合。
    \return 0 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_dhe_psk(ssl);
    if (ret != 0) {
        // PSKハンドシェイクのDHE無効化の設定に失敗しました。
    }
    \endcode

    \sa wolfSSL_CTX_no_dhe_psk
*/
int  wolfSSL_no_dhe_psk(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数は、鍵のロールオーバーを強制するために、TLS v1.3クライアントまたはサーバwolfSSLで呼び出されます。KeyUpdateメッセージがピアに送信され、暗号化用の新しい鍵が計算されます。ピアはKeyUpdateメッセージを送り返し、その後新しい復号鍵が計算されます。この関数は、ハンドシェイクが完了した後にのみ呼び出すことができます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return BAD_FUNC_ARG sslがNULLまたはTLS v1.3を使用していない場合。
    \return WANT_WRITE 書き込みの準備ができていない場合。
    \return WOLFSSL_SUCCESS 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_update_keys(ssl);
    if (ret == WANT_WRITE) {
        // I/Oの準備ができたら再度呼び出す必要があります。
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // 鍵更新の送信に失敗しました。
    }
    \endcode

    \sa wolfSSL_write
*/
int  wolfSSL_update_keys(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数は、鍵のロールオーバーが進行中かどうかを判断するために、TLS v1.3クライアントまたはサーバwolfSSLで呼び出されます。wolfSSL_update_keys()が呼び出されると、KeyUpdateメッセージが送信され、暗号化鍵が更新されます。復号鍵は、応答を受信したときに更新されます。

    \param [in] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [out] required 鍵更新応答が不要な場合は0。鍵更新応答が必要な場合は1。

    \return 0 成功した場合。
    \return BAD_FUNC_ARG sslがNULLまたはTLS v1.3を使用していない場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int required;
    ...
    ret = wolfSSL_key_update_response(ssl, &required);
    if (ret != 0) {
        // 不正なパラメータ
    }
    if (required) {
        // 暗号化鍵が更新され、復号鍵を変更するための応答を待っています。
    }
    \endcode

    \sa wolfSSL_update_keys
*/
int  wolfSSL_key_update_response(WOLFSSL* ssl, int* required);

/*!
    \ingroup Setup

    \brief この関数は、サーバからの要求に応じてクライアント証明書をハンドシェイク後に送信できるようにするために、TLS v1.3クライアントwolfSSLコンテキストで呼び出されます。これは、クライアント認証が必要なページとそうでないページを持つWebサーバに接続する際に便利です。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。

    \return BAD_FUNC_ARG ctxがNULLまたはTLS v1.3を使用していない場合。
    \return SIDE_ERROR サーバで呼び出された場合。
    \return 0 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ctx);
    if (ret != 0) {
        // ハンドシェイク後認証の許可に失敗しました。
    }
    \endcode

    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_CTX_allow_post_handshake_auth(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief この関数は、サーバからの要求に応じてクライアント証明書をハンドシェイク後に送信できるようにするために、TLS v1.3クライアントwolfSSLで呼び出されます。Post-Handshake Client Authentication拡張がClientHelloで送信されます。これは、クライアント認証が必要なページとそうでないページを持つWebサーバに接続する際に便利です。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return BAD_FUNC_ARG sslがNULLまたはTLS v1.3を使用していない場合。
    \return SIDE_ERROR サーバで呼び出された場合。
    \return 0 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ssl);
    if (ret != 0) {
        // ハンドシェイク後認証の許可に失敗しました。
    }
    \endcode

    \sa wolfSSL_CTX_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_allow_post_handshake_auth(WOLFSSL* ssl);

/*!    \ingroup IO

    \brief この関数は、TLS v1.3クライアントからクライアント証明書を要求します。これは、Webサーバがクライアント認証を必要とするページと必要としないページの両方を提供している場合に便利です。接続上で最大256回の要求を送信できます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return BAD_FUNC_ARG sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return WANT_WRITE 書き込みの準備ができていない場合。
    \return SIDE_ERROR クライアントで呼び出された場合。
    \return NOT_READY_ERROR ハンドシェイクが完了していないときに呼び出された場合。
    \return POST_HAND_AUTH_ERROR ポストハンドシェイク認証が許可されていない場合。
    \return MEMORY_E 動的メモリ割り当てが失敗した場合。
    \return WOLFSSL_SUCCESS 成功時。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_request_certificate(ssl);
    if (ret == WANT_WRITE) {
        // I/Oの準備ができたら再度呼び出す必要があります
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // クライアント証明書の要求に失敗しました
    }
    \endcode

    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_write
*/
int  wolfSSL_request_certificate(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数は、wolfSSLコンテキストで優先順位に従って許可する楕円曲線グループのリストを設定します。リストはnull終端のテキスト文字列で、コロン区切りのリストです。TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定するには、この関数を呼び出してください。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in] list 楕円曲線グループのコロン区切りリストである文字列。

    \return WOLFSSL_FAILURE ポインタパラメータがNULLの場合、グループがWOLFSSL_MAX_GROUP_COUNTを超える場合、グループ名が認識されない場合、またはTLS v1.3を使用していない場合。
    \return WOLFSSL_SUCCESS 成功時。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ctx, list);
    if (ret != WOLFSSL_SUCCESS) {
        // グループリストの設定に失敗しました
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

    \brief この関数は、wolfSSLで優先順位に従って許可する楕円曲線グループのリストを設定します。リストはnull終端のテキスト文字列で、コロン区切りのリストです。TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定するには、この関数を呼び出してください。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] list 鍵交換グループのコロン区切りリストである文字列。

    \return WOLFSSL_FAILURE ポインタパラメータがNULLの場合、グループがWOLFSSL_MAX_GROUP_COUNTを超える場合、グループ名が認識されない場合、またはTLS v1.3を使用していない場合。
    \return WOLFSSL_SUCCESS 成功時。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl, list);
    if (ret != WOLFSSL_SUCCESS) {
        // グループリストの設定に失敗しました
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

    \brief この関数は、TLS v1.3ハンドシェイクでクライアントが優先的に使用したい鍵交換グループを返します。ハンドシェイク完了後にこの関数を呼び出して、サーバが優先するグループを判定し、この情報を将来の接続で使用して鍵交換用の鍵ペアを事前生成できます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return BAD_FUNC_ARG sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return SIDE_ERROR サーバで呼び出された場合。
    \return NOT_READY_ERROR ハンドシェイク完了前に呼び出された場合。
    \return Group identifier 成功時、グループ識別子。

    _Example_
    \code
    int ret;
    int group;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl)
    if (ret < 0) {
        // グループの取得に失敗しました
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

    \brief この関数は、wolfSSLコンテキストで優先順位に従って許可する楕円曲線グループのリストを設定します。リストはグループ識別子の配列で、識別子の数はcountで指定されます。TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定するには、この関数を呼び出してください。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in] groups 識別子による鍵交換グループのリスト。
    \param [in] count groups内の鍵交換グループの数。

    \return BAD_FUNC_ARG ポインタパラメータがnullの場合、グループ数がWOLFSSL_MAX_GROUP_COUNTを超える場合、またはTLS v1.3を使用していない場合。
    \return WOLFSSL_SUCCESS 成功時。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    int* groups = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = 2;
    ...
    ret = wolfSSL_CTX_set1_groups_list(ctx, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // グループリストの設定に失敗しました
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

    \brief この関数は、wolfSSLで許可する楕円曲線グループのリストを設定します。リストはグループ識別子の配列で、識別子の数はcountで指定されます。TLS v1.3接続で使用する鍵交換楕円曲線パラメータを設定するには、この関数を呼び出してください。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] groups 識別子による鍵交換グループのリスト。
    \param [in] count groups内の鍵交換グループの数。

    \return BAD_FUNC_ARG ポインタパラメータがnullの場合、グループ数がWOLFSSL_MAX_GROUP_COUNTを超える場合、識別子のいずれかが認識されない場合、またはTLS v1.3を使用していない場合。
    \return WOLFSSL_SUCCESS 成功時。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int* groups = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = 2;
    ...
    ret = wolfSSL_set_groups(ssl, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // グループリストの設定に失敗しました
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

    \brief この関数はクライアント側で呼び出され、サーバとのTLS v1.3ハンドシェイクを開始します。この関数が呼び出されるとき、基礎となる通信チャネルはすでに設定されています。wolfSSL_connect()はブロッキングI/Oと非ブロッキングI/Oの両方で動作します。基礎となるI/Oが非ブロッキングの場合、基礎となるI/OがwolfSSL_connect()がハンドシェイクを続行するために必要なものを満たせない場合、wolfSSL_connect()は返されます。この場合、wolfSSL_get_error()を呼び出すとSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかが返されます。呼び出し側プロセスは、基礎となるI/Oの準備ができたときにwolfSSL_connect()の呼び出しを繰り返す必要があり、wolfSSLは中断したところから再開します。非ブロッキングソケットを使用する場合、何もする必要はありませんが、select()を使用して必要な条件を確認できます。基礎となるI/OがブロッキングI/Oの場合、wolfSSL_connect()はハンドシェイクが完了するかエラーが発生するまで返されません。wolfSSLは証明書検証にOpenSSLとは異なるアプローチを取ります。クライアントのデフォルトポリシーはサーバを検証することです。つまり、サーバを検証するためのCAをロードしない場合、接続エラー「検証できません(-155)」が発生します。サーバの検証が失敗してもSSL_connectが成功するというOpenSSLの動作を模倣し、セキュリティを低下させたい場合は、SSL_new()を呼び出す前にSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0)を呼び出すことでこれを行うことができます。ただし、これは推奨されません。

    \return SSL_SUCCESS 成功時。
    \return SSL_FATAL_ERROR エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出してください。

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
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept_TLSv13
    \sa wolfSSL_accept
*/
int  wolfSSL_connect_TLSv13(WOLFSSL*);

/*!
    \ingroup IO

    \brief この関数はサーバ側で呼び出され、SSL/TLSクライアントがSSL/TLSハンドシェイクを開始するのを待ちます。この関数が呼び出されるとき、基礎となる通信チャネルはすでに設定されています。wolfSSL_accept()はブロッキングI/Oと非ブロッキングI/Oの両方で動作します。基礎となるI/Oが非ブロッキングの場合、基礎となるI/OがwolfSSL_accept()がハンドシェイクを続行するために必要なものを満たせない場合、wolfSSL_accept()は返されます。この場合、wolfSSL_get_error()を呼び出すとSSL_ERROR_WANT_READまたはSSL_ERROR_WANT_WRITEのいずれかが返されます。呼び出し側プロセスは、データが読み取り可能になったときにwolfSSL_acceptの呼び出しを繰り返す必要があり、wolfSSLは中断したところから再開します。非ブロッキングソケットを使用する場合、何もする必要はありませんが、select()を使用して必要な条件を確認できます。基礎となるI/OがブロッキングI/Oの場合、wolfSSL_accept()はハンドシェイクが完了するかエラーが発生するまで返されません。TLS v1.3接続を期待する場合にこの関数を呼び出してください。ただし、古いバージョンのClientHelloメッセージもサポートされています。

    \return SSL_SUCCESS 成功時。
    \return SSL_FATAL_ERROR エラーが発生した場合に返されます。より詳細なエラーコードを取得するには、wolfSSL_get_error()を呼び出してください。

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
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
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

    \brief この関数は、TLS v1.3クライアントまたはサーバがwolfSSLコンテキストを使用して交換する意思のある早期データの最大量を設定します。リプレイ攻撃を軽減するために処理する早期データの量を制限するには、この関数を呼び出してください。早期データは、セッションチケットが送信された接続の鍵から派生した鍵によって保護されるため、セッションチケットが再開に使用されるたびに同じになります。この値は再開用のセッションチケットに含まれます。サーバの値がゼロの場合、セッションチケットを使用してクライアントが早期データを送信しないことを示します。クライアントの値がゼロの場合、クライアントが早期データを送信しないことを示します。早期データのバイト数は、アプリケーションで実用的に可能な限り低く保つことをお勧めします。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in] sz 受け入れる早期データの量(バイト単位)。

    \return BAD_FUNC_ARG ctxがNULLの場合、またはTLS v1.3を使用していない場合。
    \return 0 成功時。

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_set_max_early_data(ctx, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // グループリストの設定に失敗しました
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

    \brief この関数は、TLS v1.3クライアントまたはサーバが交換する意思のある早期データの最大量を設定します。リプレイ攻撃を軽減するために処理する早期データの量を制限するには、この関数を呼び出してください。早期データは、セッションチケットが送信された接続の鍵から派生した鍵によって保護されるため、セッションチケットが再開に使用されるたびに同じになります。この値は再開用のセッションチケットに含まれます。サーバの値がゼロの場合、セッションチケットを使用してクライアントが早期データを送信しないことを示します。クライアントの値がゼロの場合、クライアントが早期データを送信しないことを示します。早期データのバイト数は、アプリケーションで実用的に可能な限り低く保つことをお勧めします。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] sz クライアントから受け入れる早期データの量(バイト単位)。

    \return BAD_FUNC_ARG sslがNULLの場合、またはTLS v1.3を使用していない場合。
    \return 0 成功時。    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_set_max_early_data(ssl, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // グループリストの設定に失敗しました
    }
    \endcode

    \sa wolfSSL_CTX_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_set_max_early_data(WOLFSSL* ssl, unsigned int sz);

/*!
    \ingroup IO

    \brief この関数は再開時にサーバーにアーリーデータを書き込みます。サーバーに接続してハンドシェイクでデータを送信するには、wolfSSL_connect()またはwolfSSL_connect_TLSv13()の代わりにこの関数を呼び出します。この関数はクライアントでのみ使用されます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] data サーバーに書き込むアーリーデータを保持するバッファ。
    \param [in] sz 書き込むアーリーデータの量(バイト単位)。
    \param [out] outSz 書き込まれたアーリーデータの量(バイト単位)。

    \return BAD_FUNC_ARG ポインタパラメータがNULL、szが0未満、またはTLSv1.3を使用していない場合。
    \return SIDE_ERROR サーバーで呼び出された場合。
    \return WOLFSSL_FATAL_ERROR 接続が確立されなかった場合。
    \return WOLFSSL_SUCCESS 成功した場合。

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
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        goto err_label;
    }
    if (outSz < sizeof(earlyData)) {
        // すべてのアーリーデータが送信されませんでした
    }
    ret = wolfSSL_connect_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
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

    \brief この関数は再開時にクライアントからのアーリーデータを読み取ります。クライアントを受け入れ、ハンドシェイクでアーリーデータを読み取るには、wolfSSL_accept()またはwolfSSL_accept_TLSv13()の代わりにこの関数を呼び出します。wolfSSL_is_init_finished()がtrueを返すまで関数を呼び出す必要があります。アーリーデータは複数のメッセージでクライアントから送信される場合があります。アーリーデータがない場合、ハンドシェイクは通常通り処理されます。この関数はサーバーでのみ使用されます。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [out] data クライアントから読み取ったアーリーデータを保持するバッファ。
    \param [in] sz バッファのサイズ(バイト単位)。
    \param [out] outSz 読み取ったアーリーデータのバイト数。

    \return BAD_FUNC_ARG ポインタパラメータがNULL、szが0未満、またはTLSv1.3を使用していない場合。
    \return SIDE_ERROR クライアントで呼び出された場合。
    \return WOLFSSL_FATAL_ERROR 接続の受け入れが失敗した場合。
    \return 読み取ったアーリーデータのバイト数(ゼロの場合もあります)。

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    byte earlyData[128];
    int outSz;
    char buffer[80];
    ...

    do {
        ret = wolfSSL_read_early_data(ssl, earlyData, sizeof(earlyData), &outSz);
        if (ret < 0) {
            err = wolfSSL_get_error(ssl, ret);
            printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        }
        if (outSz > 0) {
            // アーリーデータが利用可能
        }
    } while (!wolfSSL_is_init_finished(ssl));
    \endcode

    \sa wolfSSL_write_early_data
    \sa wolfSSL_accept
    \sa wolfSSL_accept_TLSv13
*/
int  wolfSSL_read_early_data(WOLFSSL* ssl, void* data, int sz,
    int* outSz);

/*!
    \ingroup IO

    \brief この関数はWOLFSSLオブジェクトにデータを注入するために呼び出されます。これは、データを単一の場所から読み取り、複数の接続に分割する必要がある場合に便利です。呼び出し元はwolfSSL_read()を呼び出してWOLFSSLオブジェクトから平文データを抽出する必要があります。

    \param [in] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] data sslオブジェクトに注入するデータ。
    \param [in] sz 注入するデータのバイト数。

    \return BAD_FUNC_ARG いずれかのポインタパラメータがNULLまたはsz <= 0の場合。
    \return APP_DATA_READY 読み取るべきアプリケーションデータが残っている場合。
    \return MEMORY_E 割り当てが失敗した場合。
    \return WOLFSSL_SUCCESS 成功時。

    _Example_
    \code
    byte buf[2000]
    sz = recv(fd, buf, sizeof(buf), 0);
    if (sz <= 0)
        // エラー
    if (wolfSSL_inject(ssl, buf, sz) != WOLFSSL_SUCCESS)
        // エラー
    sz = wolfSSL_read(ssl, buf, sizeof(buf);
    \endcode

    \sa wolfSSL_read
*/
int wolfSSL_inject(WOLFSSL* ssl, const void* data, int sz);

/*!
    \ingroup Setup

    \brief この関数はTLS v1.3接続のための事前共有鍵(PSK)クライアント側コールバックを設定します。コールバックはPSKアイデンティティを検索し、その鍵とハンドシェイクで使用する暗号の名前を返すために使用されます。この関数はWOLFSSL_CTX構造体のclient_psk_tls13_cbメンバーを設定します。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in] cb TLS 1.3クライアント用の事前共有鍵(PSK)コールバック。

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

    \brief この関数はTLS v1.3接続のための事前共有鍵(PSK)クライアント側コールバックを設定します。コールバックはPSKアイデンティティを検索し、その鍵とハンドシェイクで使用する暗号の名前を返すために使用されます。この関数はWOLFSSL構造体のoptionsフィールドのclient_psk_tls13_cbメンバーを設定します。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] cb TLS 1.3クライアント用の事前共有鍵(PSK)コールバック。

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

    \brief この関数はTLS v1.3接続のための事前共有鍵(PSK)サーバー側コールバックを設定します。コールバックはPSKアイデンティティを検索し、その鍵とハンドシェイクで使用する暗号の名前を返すために使用されます。この関数はWOLFSSL_CTX構造体のserver_psk_tls13_cbメンバーを設定します。

    \param [in,out] ctx wolfSSL_CTX_new()で作成されたWOLFSSL_CTX構造体へのポインタ。
    \param [in] cb TLS 1.3サーバー用の事前共有鍵(PSK)コールバック。

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

    \brief この関数はTLS v1.3接続のための事前共有鍵(PSK)サーバー側コールバックを設定します。コールバックはPSKアイデンティティを検索し、その鍵とハンドシェイクで使用する暗号の名前を返すために使用されます。この関数はWOLFSSL構造体のoptionsフィールドのserver_psk_tls13_cbメンバーを設定します。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] cb TLS 1.3サーバー用の事前共有鍵(PSK)コールバック。

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

    \brief この関数は鍵ペアの生成を含む、グループから鍵共有エントリを作成します。KeyShare拡張には鍵交換用に生成されたすべての公開鍵が含まれます。この関数が呼び出されると、指定されたグループのみが含まれます。サーバーに対して優先グループが以前に確立されている場合に、この関数を呼び出します。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param [in] group 鍵交換グループ識別子。

    \return BAD_FUNC_ARG sslがNULLの場合。
    \return MEMORY_E 動的メモリ割り当てが失敗した場合。
    \return WOLFSSL_SUCCESS 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
    if (ret != WOLFSSL_SUCCESS) {
        // 鍵共有の設定に失敗しました
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

    \brief この関数はClientHelloで鍵共有が送信されないようにするために呼び出されます。これにより、ハンドシェイクで鍵交換が必要な場合、サーバーはHelloRetryRequestで応答することになります。期待される鍵交換グループが不明で、不要な鍵の生成を避けたい場合にこの関数を呼び出します。鍵交換が必要な場合、ハンドシェイクを完了するために追加のラウンドトリップが必要になることに注意してください。

    \param [in,out] ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \return BAD_FUNC_ARG sslがNULLの場合。
    \return SIDE_ERROR サーバーで呼び出された場合。
    \return WOLFSSL_SUCCESS 成功した場合。

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_NoKeyShares(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // 鍵共有なしの設定に失敗しました
    }
    \endcode

    \sa wolfSSL_UseKeyShare
*/
int wolfSSL_NoKeyShares(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief この関数はアプリケーションがサーバーであり、TLS 1.3プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。

    \param [in] heap 静的メモリアロケータが動的メモリ割り当て時に使用するバッファへのポインタ。

    \return 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCの呼び出し時にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method_ex(NULL);
    if (method == NULL) {
        // メソッドの取得ができません
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

    \brief この関数はアプリケーションがクライアントであり、TLS 1.3プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体のメモリを割り当て、初期化します。

    \param [in] heap 静的メモリアロケータが動的メモリ割り当て時に使用するバッファへのポインタ。

    \return 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOCの呼び出し時にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常はNULLで、errnoがENOMEMに設定されます)。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;    method = wolfTLSv1_3_client_method_ex(NULL);
    if (method == NULL) {
        // メソッドを取得できません
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

    \brief この関数は、アプリケーションがサーバーであり、TLS 1.3プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体用のメモリを割り当て、初期化します。

    \return 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOC呼び出し時にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常、errnoがENOMEMに設定されたNULL)。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        // メソッドを取得できません
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

    \brief この関数は、アプリケーションがクライアントであり、TLS 1.3プロトコルのみをサポートすることを示すために使用されます。この関数は、wolfSSL_CTX_new()でSSL/TLSコンテキストを作成する際に使用される新しいwolfSSL_METHOD構造体用のメモリを割り当て、初期化します。

    \return 成功した場合、呼び出しは新しく作成されたWOLFSSL_METHOD構造体へのポインタを返します。
    \return FAIL XMALLOC呼び出し時にメモリ割り当てが失敗した場合、基礎となるmalloc()実装の失敗値が返されます(通常、errnoがENOMEMに設定されたNULL)。

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_client_method();
    if (method == NULL) {
        // メソッドを取得できません
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

    \brief この関数は、どちら側(サーバー/クライアント)であるかがまだ決定されていないことを除いて、wolfTLSv1_3_client_methodと同様のWOLFSSL_METHODを返します。

    \param [in] heap 静的メモリアロケータが動的メモリ割り当て中に使用するバッファへのポインタ。

    \return WOLFSSL_METHOD 正常に作成された場合、WOLFSSL_METHODポインタを返します。
    \return NULL メモリ割り当てエラーまたはメソッドの作成に失敗した場合はNull。

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method_ex(NULL));
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief この関数は、どちら側(サーバー/クライアント)であるかがまだ決定されていないことを除いて、wolfTLSv1_3_client_methodと同様のWOLFSSL_METHODを返します。

    \return WOLFSSL_METHOD 正常に作成された場合、WOLFSSL_METHODポインタを返します。
    \return NULL メモリ割り当てエラーまたはメソッドの作成に失敗した場合はNull。

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method());
    // ret値を確認
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method(void);

/*!
 \ingroup SSL
 \brief この関数は、テスト専用の固定/静的エフェメラル鍵を設定します。
 \return 0 鍵が正常にロードされました。
 \param ctx WOLFSSL_CTXコンテキストポインタ。
 \param keyAlgo WC_PK_TYPE_DHやWC_PK_TYPE_ECDHなどのenum wc_PkType。
 \param key 鍵ファイルパス(keySz == 0の場合)または実際の鍵バッファ(PEMまたはASN.1)。
 \param keySz 鍵サイズ("key"引数がファイルパスの場合は0である必要があります)。
 \param format WOLFSSL_FILETYPE_ASN1またはWOLFSSL_FILETYPE_PEM。
 \sa wolfSSL_CTX_get_ephemeral_key
 */
int wolfSSL_CTX_set_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief この関数は、テスト専用の固定/静的エフェメラル鍵を設定します。
 \return 0 鍵が正常にロードされました。
 \param ssl WOLFSSLオブジェクトポインタ。
 \param keyAlgo WC_PK_TYPE_DHやWC_PK_TYPE_ECDHなどのenum wc_PkType。
 \param key 鍵ファイルパス(keySz == 0の場合)または実際の鍵バッファ(PEMまたはASN.1)。
 \param keySz 鍵サイズ("key"引数がファイルパスの場合は0である必要があります)。
 \param format WOLFSSL_FILETYPE_ASN1またはWOLFSSL_FILETYPE_PEM。
 \sa wolfSSL_get_ephemeral_key
 */
int wolfSSL_set_ephemeral_key(WOLFSSL* ssl, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief この関数は、ASN.1/DERとしてロードされた鍵へのポインタを返します。
 \return 0 鍵が正常に返されました。
 \param ctx WOLFSSL_CTXコンテキストポインタ。
 \param keyAlgo WC_PK_TYPE_DHやWC_PK_TYPE_ECDHなどのenum wc_PkType。
 \param key 鍵バッファポインタ。
 \param keySz 鍵サイズポインタ。
 \sa wolfSSL_CTX_set_ephemeral_key
 */
int wolfSSL_CTX_get_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief この関数は、ASN.1/DERとしてロードされた鍵へのポインタを返します。
 \return 0 鍵が正常に返されました。
 \param ssl WOLFSSLオブジェクトポインタ。
 \param keyAlgo WC_PK_TYPE_DHやWC_PK_TYPE_ECDHなどのenum wc_PkType。
 \param key 鍵バッファポインタ。
 \param keySz 鍵サイズポインタ。
 \sa wolfSSL_set_ephemeral_key
 */
int wolfSSL_get_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief 選択したメッセージダイジェスト、パディング、およびRSA鍵でメッセージに署名します。
 \return WOLFSSL_SUCCESS 成功時、エラー時はc。
 \param type ハッシュNID。
 \param m 署名するメッセージ。おそらくこれは署名するメッセージのダイジェストになります。
 \param mLen 署名するメッセージの長さ。
 \param sigRet 出力バッファ。
 \param sigLen 入力時: sigRetバッファの長さ、出力時: sigRetに書き込まれたデータの長さ。
 \param rsa 入力の署名に使用されるRSA鍵。
 \param flag 1: 署名を出力、0: パディングされていない署名と比較すべき値を出力。注意: RSA_PKCS1_PSS_PADDINGの場合、*Verify*関数の出力をチェックするためにwc_RsaPSS_CheckPadding_ex関数を使用する必要があります。
 \param padding 使用するパディング。現在、署名にはRSA_PKCS1_PSS_PADDINGとRSA_PKCS1_PADDINGのみがサポートされています。
 */
int wolfSSL_RSA_sign_generic_padding(int type, const unsigned char* m,
                               unsigned int mLen, unsigned char* sigRet,
                               unsigned int* sigLen, WOLFSSL_RSA* rsa,
                               int flag, int padding);
/*!

\brief DTLSv1.3スタックが送信したが、まだ他のピアから確認応答されていないメッセージがあるかどうかをチェックします。

 \return 1 保留中のメッセージがある場合、それ以外は0。
 \param ssl WOLFSSLオブジェクトポインタ。
*/
int wolfSSL_dtls13_has_pending_msg(WOLFSSL *ssl);

/*!
    \ingroup SSL
    \brief セッションからEarly Dataの最大サイズを取得します。

    \param [in] s WOLFSSL_SESSIONインスタンス。

    \return セッションが派生したWOLFSSL*で設定されたmax_early_dataの値。

    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
 */
unsigned int wolfSSL_SESSION_get_max_early_data(const WOLFSSL_SESSION *s);

/*!
    \ingroup SSL
    \brief 外部データ用の新しいインデックスを取得します。このエントリは以下のAPIにも適用されます:
           - wolfSSL_CTX_get_ex_new_index
           - wolfSSL_get_ex_new_index
           - wolfSSL_SESSION_get_ex_new_index
           - wolfSSL_X509_get_ex_new_index

    \param [in] すべての入力パラメータは無視されます。コールバック関数はwolfSSLではサポートされていません。

    \return このオブジェクトクラスの外部データAPIで使用される新しいインデックス値。
 */
int wolfSSL_CRYPTO_get_ex_new_index(int, void*, void*, void*, void*);

/*!
 \ingroup Setup
 \brief この関数がクライアント側で呼び出された場合、ピアに送信できる証明書タイプを設定します。サーバー側で呼び出された場合、ピアから受け入れ可能な証明書タイプを設定します。優先順位の高い順にバッファに証明書タイプを格納します。設定をデフォルトにリセットするには、bufにNULLを渡すか、lenに0を渡します。デフォルトでは、証明書タイプはX509のみです。両側が"Raw public key"証明書を送信または受け入れることを意図している場合、WOLFSSL_CERT_TYPE_RPKをバッファに含めて設定する必要があります。

 \return WOLFSSL_SUCCESS 証明書タイプが正常に設定された場合。
 \return BAD_FUNC_ARG ctxにNULLが渡された場合、証明書タイプとして不正な値が指定された場合、bufサイズがMAX_CLIENT_CERT_TYPE_CNTを超えた場合、またはbuf内に重複する値が見つかった場合。

 \param ctx WOLFSSL_CTXオブジェクトポインタ。
 \param buf 証明書タイプが格納されるバッファ。
 \param len bufサイズ(バイト単位)(含まれる証明書タイプの数と同じ)。
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_CTX_set_client_cert_type(ctx, buf, len);
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
 \brief この関数がサーバー側で呼び出された場合、ピアに送信できる証明書タイプを設定します。クライアント側で呼び出された場合、ピアから受け入れ可能な証明書タイプを設定します。優先順位の高い順にバッファに証明書タイプを格納します。設定をデフォルトにリセットするには、bufにNULLを渡すか、lenに0を渡します。デフォルトでは、証明書タイプはX509のみです。両側が"Raw public key"証明書を送信または受け入れることを意図している場合、WOLFSSL_CERT_TYPE_RPKをバッファに含めて設定する必要があります。

 \return WOLFSSL_SUCCESS 証明書タイプが正常に設定された場合。
 \return BAD_FUNC_ARG ctxにNULLが渡された場合、証明書タイプとして不正な値が指定された場合、bufサイズがMAX_SERVER_CERT_TYPE_CNTを超えた場合、またはbuf内に重複する値が見つかった場合。

 \param ctx WOLFSSL_CTXオブジェクトポインタ。
 \param buf 証明書タイプが格納されるバッファ。
 \param len bufサイズ(バイト単位)(含まれる証明書タイプの数と同じ)。
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_CTX_set_server_cert_type(ctx, buf, len);
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
 \brief この関数がクライアント側で呼び出された場合、ピアに送信できる証明書タイプを設定します。サーバー側で呼び出された場合、ピアから受け入れ可能な証明書タイプを設定します。優先順位の高い順にバッファに証明書タイプを格納します。設定をデフォルトにリセットするには、bufにNULLを渡すか、lenに0を渡します。デフォルトでは、証明書タイプはX509のみです。両側が"Raw public key"証明書を送信または受け入れることを意図している場合、WOLFSSL_CERT_TYPE_RPKをバッファに含めて設定する必要があります。

 \return WOLFSSL_SUCCESS 証明書タイプが正常に設定された場合。
 \return BAD_FUNC_ARG ctxにNULLが渡された場合、証明書タイプとして不正な値が指定された場合、bufサイズがMAX_CLIENT_CERT_TYPE_CNTを超えた場合、またはbuf内に重複する値が見つかった場合。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param buf 証明書タイプが格納されるバッファ。
 \param len bufサイズ(バイト単位)(含まれる証明書タイプの数と同じ)。
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_set_client_cert_type(ssl, buf, len);
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
 \brief この関数がサーバー側で呼び出された場合、ピアに送信できる証明書タイプを設定します。クライアント側で呼び出された場合、ピアから受け入れ可能な証明書タイプを設定します。優先順位の高い順にバッファに証明書タイプを格納します。設定をデフォルトにリセットするには、bufにNULLを渡すか、lenに0を渡します。デフォルトでは、証明書タイプはX509のみです。両側が"Raw public key"証明書を送信または受け入れることを意図している場合、WOLFSSL_CERT_TYPE_RPKをバッファに含めて設定する必要があります。

 \return WOLFSSL_SUCCESS 証明書タイプが正常に設定された場合。
 \return BAD_FUNC_ARG ctxにNULLが渡された場合、証明書タイプとして不正な値が指定された場合、bufサイズがMAX_SERVER_CERT_TYPE_CNTを超えた場合、またはbuf内に重複する値が見つかった場合。

 \param ctx WOLFSSL_CTXオブジェクトポインタ。
 \param buf 証明書タイプが格納されるバッファ。
 \param len bufサイズ(バイト単位)(含まれる証明書タイプの数と同じ)。
    _Example_
 \code
  int ret;  WOLFSSL* ssl;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_set_server_cert_type(ssl, buf, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_set_server_cert_type(WOLFSSL* ssl, const char* buf, int len);

/*!
    \ingroup Setup

    \brief 指定されたWOLFSSL_CTXコンテキストに対してハンドシェイクメッセージグループ化を有効にします。

    この関数は、指定されたコンテキストから作成されたすべてのSSLオブジェクトに対してハンドシェイクメッセージグループ化をオンにします。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG ctxがNULLの場合。

    \param ctx WOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_set_group_messages(ctx);
    \endcode

    \sa wolfSSL_CTX_clear_group_messages
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_clear_group_messages
*/
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief 指定されたWOLFSSL_CTXコンテキストに対してハンドシェイクメッセージグループ化を無効にします。

    この関数は、指定されたコンテキストから作成されたすべてのSSLオブジェクトに対してハンドシェイクメッセージグループ化をオフにします。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG ctxがNULLの場合。

    \param ctx WOLFSSL_CTX構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_clear_group_messages(ctx);
    \endcode

    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_clear_group_messages
*/
int wolfSSL_CTX_clear_group_messages(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief 指定されたWOLFSSLオブジェクトに対してハンドシェイクメッセージグループ化を有効にします。

    この関数は、指定されたSSLオブジェクトに対してハンドシェイクメッセージグループ化をオンにします。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG sslがNULLの場合。

    \param ssl WOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_set_group_messages(ssl);
    \endcode

    \sa wolfSSL_clear_group_messages
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_CTX_clear_group_messages
*/
int wolfSSL_set_group_messages(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief 指定されたWOLFSSLオブジェクトに対してハンドシェイクメッセージグループ化を無効にします。

    この関数は、指定されたSSLオブジェクトに対してハンドシェイクメッセージグループ化をオフにします。

    \return WOLFSSL_SUCCESS 成功時。
    \return BAD_FUNC_ARG sslがNULLの場合。

    \param ssl WOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_clear_group_messages(ssl);
    \endcode

    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_CTX_clear_group_messages
*/
int wolfSSL_clear_group_messages(WOLFSSL* ssl);

/*!
 \ingroup SSL
 \brief この関数は、ClientHelloとServerHelloで行われたクライアント証明書タイプネゴシエーションの結果を返します。ネゴシエーションが発生しなかった場合、戻り値としてWOLFSSL_SUCCESSが返され、証明書タイプとしてWOLFSSL_CERT_TYPE_UNKNOWNが返されます。

 \return WOLFSSL_SUCCESS ネゴシエートされた証明書タイプを取得できた場合。
 \return BAD_FUNC_ARG ctxまたはtpにNULLが渡された場合。
 \param ssl WOLFSSLオブジェクトポインタ。
 \param tp 証明書タイプが返されるバッファ。次の3つの証明書タイプのいずれかが返されます:WOLFSSL_CERT_TYPE_RPK、WOLFSSL_CERT_TYPE_X509、またはWOLFSSL_CERT_TYPE_UNKNOWN。

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
 \brief この関数は、ClientHelloとServerHelloで行われたサーバ証明書タイプネゴシエーションの結果を返します。ネゴシエーションが発生しなかった場合、戻り値としてWOLFSSL_SUCCESSが返され、証明書タイプとしてWOLFSSL_CERT_TYPE_UNKNOWNが返されます。

 \return WOLFSSL_SUCCESS ネゴシエートされた証明書タイプを取得できた場合。
 \return BAD_FUNC_ARG ctxまたはtpにNULLが渡された場合。
 \param ssl WOLFSSLオブジェクトポインタ。
 \param tp 証明書タイプが返されるバッファ。次の3つの証明書タイプのいずれかが返されます:WOLFSSL_CERT_TYPE_RPK、WOLFSSL_CERT_TYPE_X509、またはWOLFSSL_CERT_TYPE_UNKNOWN。
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

\brief SSLオブジェクトに対してConnectionID拡張の使用を有効にします。RFC 9146およびRFC 9147を参照してください。

 \return WOLFSSL_SUCCESS 成功時、それ以外の場合はエラーコード。

 \param ssl WOLFSSLオブジェクトポインタ。

 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_use(WOLFSSL* ssl);

/*!

\brief ハンドシェイク完了後に呼び出された場合、SSLオブジェクトに対してConnectionIDが正常にネゴシエートされたかどうかを確認します。RFC 9146およびRFC 9147を参照してください。

 \return 1 ConnectionIDが正しくネゴシエートされた場合、それ以外は0。

 \param ssl WOLFSSLオブジェクトポインタ。

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_is_enabled(WOLFSSL* ssl);

/*!

\brief この接続でレコードを送信する際に相手ピアが使用するConnectionIDを設定します。RFC 9146およびRFC 9147を参照してください。ConnectionIDは最大DTLS_CID_MAX_SIZE(調整可能なコンパイル時定義)である必要があり、255バイトを超えることはできません。

 \return WOLFSSL_SUCCESS ConnectionIDが正しく設定された場合、それ以外の場合はエラーコード。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param cid 使用するConnectionID。
 \param size 提供されたConnectionIDのサイズ。

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

\brief この接続でレコードを送信する際に相手ピアが使用するConnectionIDのサイズを取得します。RFC 9146およびRFC 9147を参照してください。サイズはパラメータsizeに格納されます。

 \return WOLFSSL_SUCCESS ConnectionIDが正しくネゴシエートされた場合、それ以外の場合はエラーコード。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param size サイズが格納される符号なしint型へのポインタ。

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

\brief この接続でレコードを送信する際に相手ピアが使用するConnectionIDを、パラメータbufferが指すバッファにコピーします。RFC 9146およびRFC 9147を参照してください。bufferSzでバッファ内の利用可能なスペースを提供する必要があります。

 \return WOLFSSL_SUCCESS ConnectionIDが正しくコピーされた場合、それ以外の場合はエラーコード。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param buffer ConnectionIDがコピーされるバッファ。
 \param bufferSz buffer内の利用可能なスペース。

 \sa wolfSSL_dtls_cid_get0_rx
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

\brief 相手ピアが使用するConnectionIDを取得します。RFC 9146およびRFC 9147を参照してください。

 \return WOLFSSL_SUCCESS ConnectionIDがcidに正しく設定された場合。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param cid CIDを保持する内部メモリに設定されるポインタ。

 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get0_rx(WOLFSSL* ssl, unsigned char** cid);

/*!

\brief この接続でレコードを送信する際に使用するConnectionIDのサイズを取得します。RFC 9146およびRFC 9147を参照してください。サイズはパラメータsizeに格納されます。

 \return WOLFSSL_SUCCESS ConnectionIDサイズが正しく格納された場合、それ以外の場合はエラーコード。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param size サイズが格納される符号なしint型へのポインタ。

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_tx_size(WOLFSSL* ssl, unsigned int* size);

/*!

\brief この接続でレコードを送信する際に使用するConnectionIDを、パラメータbufferが指すバッファにコピーします。RFC 9146およびRFC 9147を参照してください。bufferSzで利用可能なサイズを提供する必要があります。

 \return WOLFSSL_SUCCESS ConnectionIDが正しくコピーされた場合、それ以外の場合はエラーコード。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param buffer ConnectionIDがコピーされるバッファ。
 \param bufferSz buffer内の利用可能なスペース。

 \sa wolfSSL_dtls_cid_get0_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
int wolfSSL_dtls_cid_get_tx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);

/*!

\brief この接続でレコードを送信する際に使用するConnectionIDを取得します。RFC 9146およびRFC 9147を参照してください。

 \return WOLFSSL_SUCCESS ConnectionIDが正しく取得された場合、それ以外の場合はエラーコード。

 \param ssl WOLFSSLオブジェクトポインタ。
 \param cid CIDを保持する内部メモリに設定されるポインタ。

 \sa wolfSSL_dtls_cid_get_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
int wolfSSL_dtls_cid_get0_tx(WOLFSSL* ssl, unsigned char** cid);

/*!

\brief レコードデータグラム/メッセージからConnectionIDを抽出します。RFC 9146およびRFC 9147を参照してください。

 \param msg ネットワークから読み取られたデータグラムを保持するバッファ。
 \param msgSz msgのサイズ(バイト単位)。
 \param cid msgバッファ内のCIDの開始位置へのポインタ。
 \param cidSz 期待されるCIDのサイズ。レコード層にはCIDサイズフィールドがないため、CIDのサイズを事前に知っている必要があります。すべての接続に定数CIDを使用することを推奨します。

 \sa wolfSSL_dtls_cid_get_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
const unsigned char* wolfSSL_dtls_cid_parse(const unsigned char* msg,
        unsigned int msgSz, unsigned int cidSz);

/*!
    \ingroup TLS
    \brief サーバ側では、この関数は証明書要求でクライアントに送信されるCA名のリストを設定します。これは、サーバがサポートするCAのヒントとして機能します。

    クライアント側では、この関数は効果がありません。

    \param [in] ctx wolfSSLコンテキストへのポインタ。
    \param [in] names 設定される名前のリスト。

    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX* ctx,
                                    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief これは、wolfSSL_CTX_set_client_CA_listを介して以前に設定されたリストを取得します。リストが設定されていない場合はNULLを返します。

    \param [in] ctx wolfSSLコンテキストへのポインタ。
    \return CA名を含むWOLFSSL_X509_NAMEのスタック。

    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_CTX_get_client_CA_list(
        const WOLFSSL_CTX *ctx);

/*!
    \ingroup TLS
    \brief wolfSSL_CTX_set_client_CA_listと同じですが、セッション固有です。CAリストがコンテキストとセッションの両方に設定されている場合、セッション上のリストが使用されます。

    \param [in] ssl WOLFSSLオブジェクトへのポインタ。
    \param [in] names 設定する名前のリスト。

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_set_client_CA_list(WOLFSSL* ssl,
                                    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief サーバ側では、wolfSSL_set_client_CA_listを介して以前に設定されたリストを取得します。何も設定されていない場合は、wolfSSL_CTX_set_client_CA_listを介して以前に設定されたリストを返します。リストが全く設定されていない場合は、NULLを返します。

    クライアント側では、サーバから受信したリストを取得します。何も受信していない場合はNULLを返します。wolfSSL_CTX_set_cert_cbを使用して、サーバから証明書要求を受信したときに証明書を動的にロードするコールバックを登録できます。

    \param [in] ssl WOLFSSLオブジェクトへのポインタ。
    \return CA名を含むWOLFSSL_X509_NAMEのスタック。

    \sa wolfSSL_CTX_set_cert_cb
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK* wolfSSL_get_client_CA_list(
            const WOLFSSL* ssl);

/*!
    \ingroup TLS
    \brief この関数は、ピアの認証でサポートされているCAのヒントとしてピアに送信されるCA名のリストを設定します。

    TLS >= 1.3では、これはクライアントとサーバ間の両方向でサポートされています。サーバ側では、CA名はCertificateRequestの一部として送信されるため、この関数は*_set_client_CA_listと同等です。クライアント側では、これらはClientHelloの一部として送信されます。

    TLS < 1.3では、クライアントからサーバへのCA名の送信はサポートされていないため、この関数はwolfSSL_CTX_set_client_CA_listと同等です。

    *_set_client_CA_listと*_set0_CA_listを介して設定されたリストは内部的に別々であることに注意してください。つまり、*_get_client_CA_listを呼び出しても*_set0_CA_listを介して設定されたリストは取得されず、その逆も同様です。両方が設定されている場合、サーバはクライアントにCA名を送信する際に*_set0_CA_listを無視します。

    \param [in] ctx wolfSSLコンテキストへのポインタ。
    \param [in] names 設定する名前のリスト。

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_CTX_set0_CA_list(WOLFSSL_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief これは、wolfSSL_CTX_set0_CA_listを介して以前に設定されたリストを取得します。リストが設定されていない場合はNULLを返します。

    \param [in] ctx wolfSSLコンテキストへのポインタ。
    \return CA名を含むWOLFSSL_X509_NAMEのスタック。

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_CTX_get0_CA_list(
        const WOLFSSL_CTX *ctx);

/*!
    \ingroup TLS
    \brief wolfSSL_CTX_set0_CA_listと同じですが、セッション固有です。CAリストがコンテキストとセッションの両方に設定されている場合、セッション上のリストが使用されます。

    \param [in] ssl WOLFSSLオブジェクトへのポインタ。
    \param [in] names 設定する名前のリスト。

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_set0_CA_list(WOLFSSL *ssl,
        WOLF_STACK_OF(WOLFSSL_X509_NAME) *names);

/*!
    \ingroup TLS
    \brief これは、wolfSSL_set0_CA_listを介して以前に設定されたリストを取得します。何も設定されていない場合は、wolfSSL_CTX_set0_CA_listを介して以前に設定されたリストを返します。リストが全く設定されていない場合は、NULLを返します。

    \param [in] ssl WOLFSSLオブジェクトへのポインタ。
    \return CA名を含むWOLFSSL_X509_NAMEのスタック。

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_get0_CA_list(
        const WOLFSSL *ssl);

/*!
    \ingroup TLS
    \brief これは、ピアから受信したCAリストを返します。

    クライアント側では、これはサーバがCertificateRequestで送信したリストであり、この関数はwolfSSL_get_client_CA_listと同等です。

    サーバ側では、これはTLS >= 1.3でクライアントがClientHelloメッセージで送信したリストです。TLS < 1.3では、この関数はサーバ側で常にNULLを返します。

    wolfSSL_CTX_set_cert_cbを使用して、ピアからCAリストを受信したときに証明書を動的にロードするコールバックを登録できます。

    \param [in] ssl WOLFSSLオブジェクトへのポインタ。
    \return CA名を含むWOLFSSL_X509_NAMEのスタック。

    \sa wolfSSL_CTX_set_cert_cb
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
*/
WOLFSSL_STACK *wolfSSL_get0_peer_CA_list(const WOLFSSL *ssl);

/*!
    \ingroup TLS
    \brief この関数は、証明書が使用される直前に呼び出されるコールバックを設定し、アプリケーションが証明書を検査、設定、またはクリアできるようにします。例えば、ピアから送信されたCAリストに反応することができます。

    \param [in] ctx wolfSSLコンテキストへのポインタ。
    \param [in] cb コールバックへの関数ポインタ。
    \param [in] arg コールバックに渡されるポインタ。

    \sa wolfSSL_get0_peer_CA_list
    \sa wolfSSL_get_client_CA_list
*/
void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx,
    int (*cb)(WOLFSSL *, void *), void *arg);

/*!
    \ingroup TLS

    \brief この関数は、クライアントが提供する暗号スイートと署名アルゴリズムの生のリストを返します。リストは、wolfSSL_CTX_set_cert_cb()で設定されたコールバック内でのみ保存され、返されます。これは、利用可能な暗号スイートと署名アルゴリズムに基づいて証明書と鍵を動的にロードできるようにするのに便利です。

    \param [in] ssl リストを抽出するWOLFSSLオブジェクト。
    \param [out] optional suites クライアント暗号スイートの生の未フィルタリストリスト。
    \param [out] optional suiteSz suitesのサイズ(バイト単位)。
    \param [out] optional hashSigAlgo クライアント署名アルゴリズムの生の未フィルタリストリスト。
    \param [out] optional hashSigAlgoSz hashSigAlgoのサイズ(バイト単位)。
    \return WOLFSSL_SUCCESS スイートが利用可能な場合。
    \return WOLFSSL_FAILURE スイートが利用できない場合。

    _Example_
    \code
    int certCB(WOLFSSL* ssl, void* arg)
    {
        const byte* suites = NULL;
        word16 suiteSz = 0;
        const byte* hashSigAlgo = NULL;
        word16 hashSigAlgoSz = 0;

        wolfSSL_get_client_suites_sigalgs(ssl, &suites, &suiteSz, &hashSigAlgo,
                &hashSigAlgoSz);

        // 暗号スイートとsigalgsに基づいてロードする証明書を選択
    }

    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method_ex(NULL));
    wolfSSL_CTX_set_cert_cb(ctx, certCB, NULL);
    \endcode

    \sa wolfSSL_get_ciphersuite_info
    \sa wolfSSL_get_sigalg_info
*/
int wolfSSL_get_client_suites_sigalgs(const WOLFSSL* ssl,
        const byte** suites, word16* suiteSz,
        const byte** hashSigAlgo, word16* hashSigAlgoSz);

/*!
    \ingroup TLS

    \brief これは、生の暗号スイートバイトから直接暗号スイートに関する情報を返します。

    \param [in] first 暗号スイートの最初のバイト。
    \param [in] second 暗号スイートの2番目のバイト。

    \return WOLFSSL_CIPHERSUITE_INFO 暗号スイートで使用される認証のタイプに関する情報を含む構造体。

    _Example_
    \code
    WOLFSSL_CIPHERSUITE_INFO info =
            wolfSSL_get_ciphersuite_info(suites[0], suites[1]);
    if (info.rsaAuth)
        haveRSA = 1;
    else if (info.eccAuth)
        haveECC = 1;
    \endcode

    \sa wolfSSL_get_client_suites_sigalgs
    \sa wolfSSL_get_sigalg_info
*/
WOLFSSL_CIPHERSUITE_INFO wolfSSL_get_ciphersuite_info(byte first,
        byte second);

/*!
    \ingroup TLS

    \brief これは、生の暗号スイートバイトから直接ハッシュおよび署名アルゴリズムに関する情報を返します。

    \param [in] first ハッシュおよび署名アルゴリズムの最初のバイト。
    \param [in] second ハッシュおよび署名アルゴリズムの2番目のバイト。
    \param [out] hashAlgo MACアルゴリズムのenum wc_HashType。
    \param [out] sigAlgo 認証アルゴリズムのenum Key_Sum。

    \return 0            情報が正しく設定された場合。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合、またはバイトが認識されるsigalgスイートでない場合。

    _Example_
    \code
    enum wc_HashType hashAlgo;
    enum Key_Sum sigAlgo;

    wolfSSL_get_sigalg_info(hashSigAlgo[idx+0], hashSigAlgo[idx+1],
            &hashAlgo, &sigAlgo);

    if (sigAlgo == RSAk || sigAlgo == RSAPSSk)
        haveRSA = 1;
    else if (sigAlgo == ECDSAk)
        haveECC = 1;
    \endcode

    \sa wolfSSL_get_client_suites_sigalgs
    \sa wolfSSL_get_ciphersuite_info
*/
int wolfSSL_get_sigalg_info(byte first, byte second,
        int* hashAlgo, int* sigAlgo);
