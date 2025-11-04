/*!
    \brief この関数は受信埋め込みコールバックです。

    \return Success この関数は読み取られたバイト数を返します。
    \return WOLFSSL_CBIO_ERR_WANT_READ 最後のエラーがSOCKET_EWOULDBLCOKまたはSOCKET_EAGAINの場合、"Would block"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_TIMEOUT "Socket timeout"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_CONN_RST 最後のエラーがSOCKET_ECONNRESETの場合、"Connection reset"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_ISR 最後のエラーがSOCKET_EINTRの場合、"Socket interrupted"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_WANT_READ 最後のエラーがSOCKET_ECONNREFUSEDの場合、"Connection refused"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_CONN_CLOSE 最後のエラーがSOCKET_ECONNABORTEDの場合、"Connection aborted"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_GENERAL 最後のエラーが指定されていない場合、"General error"メッセージとともに返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf バッファのchar型ポインタ表現。
    \param sz バッファのサイズ。
    \param ctx ユーザー登録コンテキストへのvoid型ポインタ。デフォルトの場合、ctxはソケット記述子ポインタです。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* buf;
    int sz;
    void* ctx;
    int bytesRead = EmbedReceive(ssl, buf, sz, ctx);
    if(bytesRead <= 0){
	    // バイトが読み取られませんでした。失敗ケース。
    }
    \endcode

    \sa EmbedSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SSLSetIORecv
*/
int EmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx);

/*!
    \brief この関数は送信埋め込みコールバックです。

    \return Success この関数は送信されたバイト数を返します。
    \return WOLFSSL_CBIO_ERR_WANT_WRITE 最後のエラーがSOCKET_EWOULDBLOCKまたはSOCKET_EAGAINの場合、"Would block"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_CONN_RST 最後のエラーがSOCKET_ECONNRESETの場合、"Connection reset"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_ISR 最後のエラーがSOCKET_EINTRの場合、"Socket interrupted"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_CONN_CLOSE 最後のエラーがSOCKET_EPIPEの場合、"Socket EPIPE"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_GENERAL 最後のエラーが指定されていない場合、"General error"メッセージとともに返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf バッファを表すchar型ポインタ。
    \param sz バッファのサイズ。
    \param ctx ユーザー登録コンテキストへのvoid型ポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* buf;
    int sz;
    void* ctx;
    int dSent = EmbedSend(ssl, buf, sz, ctx);
    if(dSent <= 0){
    	// バイトが送信されませんでした。失敗ケース。
    }
    \endcode

    \sa EmbedReceive
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_SSLSetIOSend
*/
int EmbedSend(WOLFSSL* ssl, char* buf, int sz, void* ctx);

/*!
    \brief この関数は受信埋め込みコールバックです。

    \return Success 実行が成功した場合、この関数は読み取られたnbバイト数を返します。
    \return WOLFSSL_CBIO_ERR_WANT_READ 接続が拒否された場合、または関数で'would block'エラーがスローされた場合に返されます。
    \return WOLFSSL_CBIO_ERR_TIMEOUT ソケットがタイムアウトした場合に返されます。
    \return WOLFSSL_CBIO_ERR_CONN_RST 接続がリセットされた場合に返されます。
    \return WOLFSSL_CBIO_ERR_ISR ソケットが中断された場合に返されます。
    \return WOLFSSL_CBIO_ERR_GENERAL 一般的なエラーがあった場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf バッファへのconst char型ポインタ。
    \param sz バッファのサイズを表すint型。
    \param ctx WOLFSSL_CTXコンテキストへのvoid型ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    char* buf;
    int sz = sizeof(buf)/sizeof(char);
    (void*)ctx;
    …
    int nb = EmbedReceiveFrom(ssl, buf, sz, ctx);
    if(nb > 0){
	    // nbは書き込まれたバイト数で正の値です
    }
    \endcode

    \sa EmbedSendTo
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SSLSetIORecv
    \sa wolfSSL_dtls_get_current_timeout
*/
int EmbedReceiveFrom(WOLFSSL* ssl, char* buf, int sz, void*);

/*!
    \brief この関数は送信埋め込みコールバックです。

    \return Success この関数は送信されたバイト数を返します。
    \return WOLFSSL_CBIO_ERR_WANT_WRITE 最後のエラーがSOCKET_EWOULDBLOCKまたはSOCKET_EAGAINエラーの場合、"Would Block"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_CONN_RST 最後のエラーがSOCKET_ECONNRESETの場合、"Connection reset"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_ISR 最後のエラーがSOCKET_EINTRの場合、"Socket interrupted"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_CONN_CLOSE 最後のエラーがWOLFSSL_CBIO_ERR_CONN_CLOSEの場合、"Socket EPIPE"メッセージとともに返されます。
    \return WOLFSSL_CBIO_ERR_GENERAL 最後のエラーが指定されていない場合、"General error"メッセージとともに返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf バッファを表すchar型ポインタ。
    \param sz バッファのサイズ。
    \param ctx ユーザー登録コンテキストへのvoid型ポインタ。デフォルトの場合はWOLFSSL_DTLS_CTX構造体です。

    _Example_
    \code
    WOLFSSL* ssl;
    …
    char* buf;
    int sz;
    void* ctx;

    int sEmbed = EmbedSendto(ssl, buf, sz, ctx);
    if(sEmbed <= 0){
    	// バイトが送信されませんでした。失敗ケース。
    }
    \endcode

    \sa EmbedReceiveFrom
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_SSLSetIOSend
*/
int EmbedSendTo(WOLFSSL* ssl, char* buf, int sz, void* ctx);

/*!
    \brief この関数はDTLS Generate Cookieコールバックです。

    \return Success この関数はバッファにコピーされたバイト数を返します。
    \return GEN_COOKIE_E EmbedGenerateCookieでgetpeernameが失敗した場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param buf バッファを表すbyte型ポインタ。XMEMCPY()の宛先です。
    \param sz バッファのサイズ。
    \param ctx ユーザー登録コンテキストへのvoid型ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte buffer[BUFFER_SIZE];
    int sz = sizeof(buffer)/sizeof(byte);
    void* ctx;
    …
    int ret = EmbedGenerateCookie(ssl, buffer, sz, ctx);

    if(ret > 0){
    	// EmbedGenerateCookieの成功コードブロック
    }
    \endcode

    \sa wolfSSL_CTX_SetGenCookie
*/
int EmbedGenerateCookie(WOLFSSL* ssl, unsigned char* buf,
                                           int sz, void*);

/*!
    \brief この関数は応答バッファを解放します。

    \return none 戻り値なし。

    \param ctx ヒープヒントへのvoid型ポインタ。
    \param resp 応答を表すbyte型ポインタ。

    _Example_
    \code
    void* ctx;
    byte* resp; // 応答バッファ
    …
    EmbedOcspRespFree(ctx, resp);
    \endcode

    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa wolfSSL_CertManagerEnableOCSP
*/
void EmbedOcspRespFree(void* ctx, byte* resp);

/*!
    \brief この関数は、wolfSSLが入力データを取得するための受信コールバックを登録します。
    デフォルトでは、wolfSSLはシステムのTCP recv()関数を使用するコールバックとしてEmbedReceive()を使用します。
    ユーザーは、メモリ、他のネットワークモジュール、または任意の場所から入力を取得する関数を登録できます。
    関数の動作方法とエラーコードについては、src/io.cのEmbedReceive()関数をガイドとして参照してください。
    特に、データの準備ができていないノンブロッキング受信の場合はIO_ERR_WANT_READを返す必要があります。

    \return none 戻り値なし。

    \param ctx wolfSSL_CTX_new()で作成されたSSLコンテキストへのポインタ。
    \param callback wolfSSLコンテキストctxの受信コールバックとして登録される関数。この関数のシグネチャは、上記のSynopsisセクションに示されているものに従う必要があります。

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    // 受信コールバックのプロトタイプ
    int MyEmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx);
    // カスタム受信コールバックをwolfSSLに登録
    wolfSSL_CTX_SetIORecv(ctx, MyEmbedReceive);
    int MyEmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx)
    {
	    // カスタムEmbedReceive関数
    }
    \endcode

    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
*/
void wolfSSL_CTX_SetIORecv(WOLFSSL_CTX* ctx, CallbackIORecv CBIORecv);

/*!
    \brief この関数は、SSLセッションの受信コールバック関数のコンテキストを登録します。
    デフォルトでは、wolfSSLがシステムのTCPライブラリを使用している場合、wolfSSLはwolfSSL_set_fd()に渡されたファイル記述子をコンテキストとして設定します。
    独自の受信コールバックを登録した場合、セッションの特定のコンテキストを設定することができます。
    たとえば、メモリバッファを使用している場合、コンテキストはメモリバッファへのアクセス方法と場所を記述する構造体へのポインタになる可能性があります。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param rctx SSLセッション（ssl）の受信コールバック関数に登録されるコンテキストへのポインタ。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    // 例として、受信CTXとしてソケットfdを手動で設定
    wolfSSL_SetIOReadCtx(ssl, &sockfd);
    ...
    \endcode

    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_SetIOWriteCtx
*/
void wolfSSL_SetIOReadCtx( WOLFSSL* ssl, void *ctx);

/*!
    \brief この関数は、SSLセッションの送信コールバック関数のコンテキストを登録します。
    デフォルトでは、wolfSSLがシステムのTCPライブラリを使用している場合、wolfSSLはwolfSSL_set_fd()に渡されたファイル記述子をコンテキストとして設定します。
    独自の送信コールバックを登録した場合、セッションの特定のコンテキストを設定することができます。
    たとえば、メモリバッファを使用している場合、コンテキストはメモリバッファへのアクセス方法と場所を記述する構造体へのポインタになる可能性があります。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param wctx SSLセッション（ssl）の送信コールバック関数に登録されるコンテキストへのポインタ。

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    // 例として、送信CTXとしてソケットfdを手動で設定
    wolfSSL_SetIOWriteCtx(ssl, &sockfd);
    ...
    \endcode

    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_SetIOReadCtx
*/
void wolfSSL_SetIOWriteCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup IO

    \brief この関数はWOLFSSL構造体のIOCB_ReadCtxメンバーを返します。

    \return pointer この関数はWOLFSSL構造体のIOCB_ReadCtxメンバーへのvoid型ポインタを返します。
    \return NULL WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* ioRead;
    ...
    ioRead = wolfSSL_GetIOReadCtx(ssl);
    if(ioRead == NULL){
    	// 失敗ケース。sslオブジェクトがNULLでした。
    }
    \endcode

    \sa wolfSSL_GetIOWriteCtx
    \sa wolfSSL_SetIOReadFlags
    \sa wolfSSL_SetIOWriteCtx
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_CTX_SetIOSend
*/
void* wolfSSL_GetIOReadCtx( WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief この関数はWOLFSSL構造体のIOCB_WriteCtxメンバーを返します。

    \return pointer この関数はWOLFSSL構造体のIOCB_WriteCtxメンバーへのvoid型ポインタを返します。
    \return NULL WOLFSSL構造体がNULLの場合に返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL* ssl;
    void* ioWrite;
    ...
    ioWrite = wolfSSL_GetIOWriteCtx(ssl);
    if(ioWrite == NULL){
    	// 関数がNULLを返しました。
    }
    \endcode

    \sa wolfSSL_GetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_CTX_SetIOSend
*/
void* wolfSSL_GetIOWriteCtx(WOLFSSL* ssl);

/*!
    \brief この関数は、指定されたSSLセッションの受信コールバックで使用するフラグを設定します。
    受信コールバックは、デフォルトのwolfSSL EmbedReceiveコールバック、またはユーザーが指定したカスタムコールバックのいずれかです（wolfSSL_CTX_SetIORecvを参照）。
    デフォルトのフラグ値は、wolfSSL内部で0の値に設定されます。
    デフォルトのwolfSSL受信コールバックは、recv()関数を使用してソケットからデータを受信します。
    recv()のmanページより：
    「recv()関数のflagsパラメータは、次の値の1つ以上をORして形成されます：
    MSG_OOB 帯域外データを処理、MSG_PEEK 受信メッセージを覗き見、MSG_WAITALL 完全なリクエストまたはエラーを待機。
    MSG_OOBフラグは、通常のデータストリームでは受信されない帯域外データの受信を要求します。
    一部のプロトコルは、通常のデータキューの先頭に緊急データを配置するため、このフラグはそのようなプロトコルでは使用できません。
    MSG_PEEKフラグは、受信操作が受信キューの先頭からデータを返すようにしますが、そのデータをキューから削除しません。
    したがって、後続の受信呼び出しは同じデータを返します。
    MSG_WAITALLフラグは、完全なリクエストが満たされるまで操作をブロックするよう要求します。
    ただし、シグナルがキャッチされた場合、エラーまたは切断が発生した場合、または次に受信されるデータが返されたデータとは異なるタイプの場合、呼び出しは要求されたデータよりも少ないデータを返す可能性があります。」

    \return none 戻り値なし。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param flags 指定されたSSLセッション（ssl）のI/O読み取りフラグの値。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    // recvフラグを手動で0に設定
    wolfSSL_SetIOReadFlags(ssl, 0);
    ...
    \endcode

    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_SetIOReadCtx
*/
void wolfSSL_SetIOReadFlags( WOLFSSL* ssl, int flags);

/*!
    \brief この関数は、指定されたSSLセッションの送信コールバックで使用するフラグを設定します。
    送信コールバックは、デフォルトのwolfSSL EmbedSendコールバック、またはユーザーが指定したカスタムコールバックのいずれかです（wolfSSL_CTX_SetIOSendを参照）。
    デフォルトのフラグ値は、wolfSSL内部で0の値に設定されます。
    デフォルトのwolfSSL送信コールバックは、send()関数を使用してソケットからデータを送信します。
    send()のmanページより：
    「flagsパラメータには、次の1つ以上が含まれる場合があります：
    #define MSG_OOB 0x1  // 帯域外データを処理、
    #define MSG_DONTROUTE  0x4  // ルーティングをバイパス、直接インターフェースを使用。
    フラグMSG_OOBは、この概念をサポートするソケット（例：SOCK_STREAM）で「帯域外」データを送信するために使用されます。
    基礎となるプロトコルも「帯域外」データをサポートする必要があります。
    MSG_DONTROUTEは通常、診断またはルーティングプログラムによってのみ使用されます。」

    \return none 戻り値なし。

    \param ssl wolfSSL_new()で作成されたSSLセッションへのポインタ。
    \param flags 指定されたSSLセッション（ssl）のI/O送信フラグの値。

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    // 送信フラグを手動で0に設定
    wolfSSL_SetIOWriteFlags(ssl, 0);
    ...
    \endcode

    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_SetIOReadCtx
*/
void wolfSSL_SetIOWriteFlags(WOLFSSL* ssl, int flags);

/*!
    \ingroup IO

    \brief この関数は、WOLFSSL構造体内のnxCtx構造体のnxSocketおよびnxWaitメンバーを設定します。

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param nxSocket nxCTX構造体のnxSocketメンバーに設定されるNX_TCP_SOCKET型へのポインタ。
    \param waitOption nxCtx構造体のnxWaitメンバーに設定されるULONG型。

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    NX_TCP_SOCKET* nxSocket;
    ULONG waitOption;
    …
    if(ssl != NULL || nxSocket != NULL || waitOption <= 0){
    wolfSSL_SetIO_NetX(ssl, nxSocket, waitOption);
    } else {
    	// 適切なパラメータを渡す必要があります。
    }
    \endcode

    \sa set_fd
    \sa NetX_Send
    \sa NetX_Receive
*/
void wolfSSL_SetIO_NetX(WOLFSSL* ssl, NX_TCP_SOCKET* nxsocket,
                                      ULONG waitoption);

/*!
    \brief この関数は、WOLFSSL_CTX構造体のCBIOCookieメンバーのコールバックを設定します。
    CallbackGenCookie型は関数ポインタで、次のシグネチャを持ちます：
    int (*CallbackGenCookie)(WOLFSSL* ssl, unsigned char* buf, int sz, void* ctx);

    \return none 戻り値なし。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param cb CallbackGenCookieのシグネチャを持つCallbackGenCookie型の関数ポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int SetGenCookieCB(WOLFSSL* ssl, unsigned char* buf, int sz, void* ctx){
	// コールバック関数本体
    }
    …
    wolfSSL_CTX_SetGenCookie(ssl->ctx, SetGenCookieCB);
    \endcode

    \sa CallbackGenCookie
*/
void  wolfSSL_CTX_SetGenCookie(WOLFSSL_CTX* ctx, CallbackGenCookie cb);

/*!
    \ingroup Setup

    \brief この関数はWOLFSSL構造体のIOCB_CookieCtxメンバーを返します。

    \return pointer 関数はIOCB_CookieCtxに保存されているvoid型ポインタ値を返します。
    \return NULL WOLFSSL構造体がNULLの場合。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* cookie;
    ...
    cookie = wolfSSL_GetCookieCtx(ssl);
    if(cookie != NULL){
	// cookieを取得しました
    }
    \endcode

    \sa wolfSSL_SetCookieCtx
    \sa wolfSSL_CTX_SetGenCookie
*/
void* wolfSSL_GetCookieCtx(WOLFSSL* ssl);


/*!
    \ingroup Setup

    \brief この関数は、wolfSSLがWOLFSSL_ISOTPでコンパイルされている場合に使用するために、wolfSSLのISO-TPコンテキストを設定します。

    \return 0 成功時、WOLFSSL_CBIO_ERR_GENERAL 失敗時。

    \param ssl wolfSSLコンテキスト。
    \param ctx この関数が初期化するユーザー作成のISOTPコンテキスト。
    \param recv_fn ユーザーのCANバス受信コールバック。
    \param send_fn ユーザーのCANバス送信コールバック。
    \param delay_fn ユーザーのマイクロ秒粒度遅延関数。
    \param receive_delay 各CANバスパケットを遅延させる設定マイクロ秒数。
    \param receive_buffer データを受信するためのユーザー提供バッファ、ISOTP_DEFAULT_BUFFER_SIZEバイトに割り当てることを推奨。
    \param receive_buffer_size - receive_bufferのサイズ。
    \param arg recv_fnとsend_fnに送信される任意のポインタ。

    _Example_
    \code
    struct can_info can_con_info;
    isotp_wolfssl_ctx isotp_ctx;
    char *receive_buffer = malloc(ISOTP_DEFAULT_BUFFER_SIZE);
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    wolfSSL_SetIO_ISOTP(ssl, &isotp_ctx, can_receive, can_send, can_delay, 0,
            receive_buffer, ISOTP_DEFAULT_BUFFER_SIZE, &can_con_info);
    \endcode
 */
int wolfSSL_SetIO_ISOTP(WOLFSSL *ssl, isotp_wolfssl_ctx *ctx,
        can_recv_fn recv_fn, can_send_fn send_fn, can_delay_fn delay_fn,
        word32 receive_delay, char *receive_buffer, int receive_buffer_size,
        void *arg);

/*!
    \ingroup Setup

    \brief この関数はIOレイヤーからの読み取りを無効にします。

    \param ssl wolfSSLコンテキスト。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_SSLDisableRead(ssl);
    \endcode

    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SSLSetIORecv
    \sa wolfSSL_SSLEnableRead
 */
void wolfSSL_SSLDisableRead(WOLFSSL *ssl);

/*!
    \ingroup Setup

    \brief この関数はIOレイヤーからの読み取りを有効にします。
    読み取りはデフォルトで有効になっており、wolfSSL_SSLDisableRead()を元に戻すために使用する必要があります。

    \param ssl wolfSSLコンテキスト。

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_SSLDisableRead(ssl);
    ...
    wolfSSL_SSLEnableRead(ssl);
    \endcode

    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SSLSetIORecv
    \sa wolfSSL_SSLEnableRead
 */
void wolfSSL_SSLEnableRead(WOLFSSL *ssl);