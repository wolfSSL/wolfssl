/*!
    \ingroup SRP

    \brief 使用のためにSrp構造体を初期化します。

    \return 0 成功時。
    \return BAD_FUNC_ARG srpがnullの場合やSrpSideがSRP_CLIENT_SIDEまたはSRP_SERVER_SIDEでない場合など、引数に問題がある場合に返されます。
    \return NOT_COMPILED_IN 引数として渡された型がwolfCryptビルドで設定されていない場合に返されます。
    \return <0 エラー時。

    \param srp 初期化するSrp構造体。
    \param type 使用するハッシュタイプ。
    \param side 通信の側。

    _Example_
    \code
    Srp srp;
    if (wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE) != 0)
    {
        // 初期化エラー
    }
    else
    {
        wc_SrpTerm(&srp);
    }
    \endcode

    \sa wc_SrpTerm
    \sa wc_SrpSetUsername
*/
int wc_SrpInit(Srp* srp, SrpType type, SrpSide side);

/*!
    \ingroup SRP

    \brief 使用後にSrp構造体のリソースを解放します。

    \return none 戻り値なし。

    \param srp 終了するSrp構造体へのポインタ。

    _Example_
    \code
    Srp srp;
    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE);
    // srpを使用
    wc_SrpTerm(&srp)
    \endcode

    \sa wc_SrpInit
*/
void wc_SrpTerm(Srp* srp);

/*!
    \ingroup SRP

    \brief ユーザー名を設定します。この関数はwc_SrpInitの後に呼び出す必要があります。

    \return 0 ユーザー名が正常に設定されました。
    \return BAD_FUNC_ARG: srpまたはusernameがnullの場合に返されます。
    \return MEMORY_E: srp->userのメモリ割り当てに問題がある場合に返されます
    \return < 0: エラー。

    \param srp Srp構造体。
    \param username ユーザー名を含むバッファ。
    \param size ユーザー名のサイズ(バイト単位)

    _Example_
    \code
    Srp srp;
    byte username[] = "user";
    word32 usernameSize = 4;

    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE);
    if(wc_SrpSetUsername(&srp, username, usernameSize) != 0)
    {
        // ユーザー名の設定エラーが発生しました。
    }
    wc_SrpTerm(&srp);
    \endcode

    \sa wc_SrpInit
    \sa wc_SrpSetParams
    \sa wc_SrpTerm
*/
int wc_SrpSetUsername(Srp* srp, const byte* username, word32 size);

/*!
    \ingroup SRP

    \brief ユーザー名に基づいてsrpパラメータを設定します。wc_SrpSetUsernameの後に呼び出す必要があります。

    \return 0 成功
    \return BAD_FUNC_ARG srp、N、g、またはsaltがnullの場合、またはnSz < gSzの場合に返されます。
    \return SRP_CALL_ORDER_E wc_SrpSetUsernameの前にwc_SrpSetParamsが呼び出された場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param N モジュラス。N = 2q+1、[q、N]は素数。
    \param nSz Nのサイズ(バイト単位)。
    \param g Nを法とする生成元。
    \param gSz gのサイズ(バイト単位)
    \param salt 小さなランダムソルト。各ユーザー名に固有。
    \param saltSz ソルトのサイズ(バイト単位)

    _Example_
    \code
    Srp srp;
    byte username[] = "user";
    word32 usernameSize = 4;

    byte N[] = { }; // バイト配列Nの内容
    byte g[] = { }; // バイト配列gの内容
    byte salt[] = { }; // バイト配列saltの内容

    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE);
    wc_SrpSetUsername(&srp, username, usernameSize);

    if(wc_SrpSetParams(&srp, N, sizeof(N), g, sizeof(g), salt,
    sizeof(salt)) != 0)
    {
        // パラメータ設定エラー
    }
    wc_SrpTerm(&srp);
    \endcode

    \sa wc_SrpInit
    \sa wc_SrpSetUsername
    \sa wc_SrpTerm
*/
int wc_SrpSetParams(Srp* srp, const byte* N,    word32 nSz,
                                          const byte* g,    word32 gSz,
                                          const byte* salt, word32 saltSz);

/*!
    \ingroup SRP

    \brief パスワードを設定します。パスワードの設定は、srp構造体にクリアパスワードデータを永続化しません。クライアントはx = H(salt + H(user:pswd))を計算し、authフィールドに格納します。この関数はwc_SrpSetParamsの後に呼び出す必要があり、クライアント側のみです。

    \return 0 成功
    \return BAD_FUNC_ARG srpまたはpasswordがnullの場合、またはsrp->sideがSRP_CLIENT_SIDEに設定されていない場合に返されます。
    \return SRP_CALL_ORDER_E wc_SrpSetPasswordが順序外で呼び出された場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param password パスワードを含むバッファ。
    \param size パスワードのサイズ(バイト単位)。

    _Example_
    \code
    Srp srp;
    byte username[] = "user";
    word32 usernameSize = 4;
    byte password[] = "password";
    word32 passwordSize = 8;

    byte N[] = { }; // バイト配列Nの内容
    byte g[] = { }; // バイト配列gの内容
    byte salt[] = { }; // バイト配列saltの内容

    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE);
    wc_SrpSetUsername(&srp, username, usernameSize);
    wc_SrpSetParams(&srp, N, sizeof(N), g, sizeof(g), salt, sizeof(salt));

    if(wc_SrpSetPassword(&srp, password, passwordSize) != 0)
    {
        // パスワード設定エラー
    }

    wc_SrpTerm(&srp);
    \endcode

    \sa wc_SrpInit
    \sa wc_SrpSetUsername
    \sa wc_SrpSetParams
*/
int wc_SrpSetPassword(Srp* srp, const byte* password, word32 size);

/*!
    \ingroup SRP

    \brief 検証子を設定します。この関数はwc_SrpSetParamsの後に呼び出す必要があり、サーバー側のみです。

    \return 0 成功
    \return BAD_FUNC_ARG srpまたはverifierがnullの場合、またはsrp->sideがSRP_SERVER_SIDEでない場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param verifier 検証子を含む構造体。
    \param size 検証子のサイズ(バイト単位)。

    _Example_
    \code
    Srp srp;
    byte username[] = "user";
    word32 usernameSize = 4;

    byte N[] = { }; // バイト配列Nの内容
    byte g[] = { }; // バイト配列gの内容
    byte salt[] = { }; // バイト配列saltの内容
    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_SERVER_SIDE);
    wc_SrpSetUsername(&srp, username, usernameSize);
    wc_SrpSetParams(&srp, N, sizeof(N), g, sizeof(g), salt, sizeof(salt))
    byte verifier[] = { }; // 何らかの検証子の内容

    if(wc_SrpSetVerifier(&srp, verifier, sizeof(verifier)) != 0)
    {
        // 検証子設定エラー
    }

    wc_SrpTerm(&srp);
    \endcode

    \sa wc_SrpInit
    \sa wc_SrpSetParams
    \sa wc_SrpGetVerifier
*/
int wc_SrpSetVerifier(Srp* srp, const byte* verifier, word32 size);

/*!
    \ingroup SRP

    \brief 検証子を取得します。クライアントはv = g ^ x % Nで検証子を計算します。
    この関数はwc_SrpSetPasswordの後に呼び出すことができ、クライアント側のみです。

    \return 0 成功
    \return BAD_FUNC_ARG srp、verifier、またはsizeがnullの場合、またはsrp->sideがSRP_CLIENT_SIDEでない場合に返されます。
    \return SRP_CALL_ORDER_E wc_SrpGetVerifierが順序外で呼び出された場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param verifier 検証子を書き込むバッファ。
    \param size バッファサイズ(バイト単位)。検証子のサイズで更新されます。

    _Example_
    \code
    Srp srp;
    byte username[] = "user";
    word32 usernameSize = 4;
    byte password[] = "password";
    word32 passwordSize = 8;

    byte N[] = { }; // バイト配列Nの内容
    byte g[] = { }; // バイト配列gの内容
    byte salt[] = { }; // バイト配列saltの内容
    byte v[64];
    word32 vSz = 0;
    vSz = sizeof(v);

    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE);
    wc_SrpSetUsername(&srp, username, usernameSize);
    wc_SrpSetParams(&srp, N, sizeof(N), g, sizeof(g), salt, sizeof(salt))
    wc_SrpSetPassword(&srp, password, passwordSize)

    if( wc_SrpGetVerifier(&srp, v, &vSz ) != 0)
    {
        // 検証子取得エラー
    }
    wc_SrpTerm(&srp);
    \endcode

    \sa wc_SrpSetVerifier
    \sa wc_SrpSetPassword
*/
int wc_SrpGetVerifier(Srp* srp, byte* verifier, word32* size);

/*!
    \ingroup SRP

    \brief 秘密エフェメラル値を設定します。秘密エフェメラル値は次のように知られています:
    クライアント側ではa。a = random()
    サーバー側ではb。b = random()
    この関数は単体テストケースや、開発者が外部の乱数ソースを使用してエフェメラル値を設定したい場合に便利です。この関数はwc_SrpGetPublicの前に呼び出すことができます。

    \return 0 成功
    \return BAD_FUNC_ARG srp、private、またはsizeがnullの場合に返されます。
    \return SRP_CALL_ORDER_E wc_SrpSetPrivateが順序外で呼び出された場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param priv エフェメラル値。
    \param size privateのサイズ(バイト単位)。

    _Example_
    \code
    Srp srp;
    byte username[] = "user";
    word32 usernameSize = 4;

    byte N[] = { }; // バイト配列Nの内容
    byte g[] = { }; // バイト配列gの内容
    byte salt[] = { }; // バイト配列saltの内容
    byte verifier = { }; // 何らかの検証子の内容
    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_SERVER_SIDE);
    wc_SrpSetUsername(&srp, username, usernameSize);
    wc_SrpSetParams(&srp, N, sizeof(N), g, sizeof(g), salt, sizeof(salt))
    wc_SrpSetVerifier(&srp, verifier, sizeof(verifier))

    byte b[] = { }; // 何らかのエフェメラル値
    if( wc_SrpSetPrivate(&srp, b, sizeof(b)) != 0)
    {
        // 秘密エフェメラル設定エラー
    }

    wc_SrpTerm(&srp);
    \endcode

    \sa wc_SrpGetPublic
*/
int wc_SrpSetPrivate(Srp* srp, const byte* priv, word32 size);

/*!
    \ingroup SRP

    \brief 公開エフェメラル値を取得します。公開エフェメラル値は次のように知られています:
    クライアント側ではA。A = g ^ a % N
    サーバー側ではB。B = (k * v + (g ˆ b % N)) % N
    この関数はwc_SrpSetPasswordまたはwc_SrpSetVerifierの後に呼び出す必要があります。
    関数wc_SrpSetPrivateはwc_SrpGetPublicの前に呼び出すことができます。

    \return 0 成功
    \return BAD_FUNC_ARG srp、pub、またはsizeがnullの場合に返されます。
    \return SRP_CALL_ORDER_E wc_SrpGetPublicが順序外で呼び出された場合に返されます。
    \return BUFFER_E size < srp.Nの場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param pub 公開エフェメラル値を書き込むバッファ。
    \param size バッファサイズ(バイト単位)。エフェメラル値のサイズで更新されます。

    _Example_
    \code
    Srp srp;
    byte username[] = "user";
    word32 usernameSize = 4;
    byte password[] = "password";
    word32 passwordSize = 8;

    byte N[] = { }; // バイト配列Nの内容
    byte g[] = { }; // バイト配列gの内容
    byte salt[] = { }; // バイト配列saltの内容
    wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE);
    wc_SrpSetUsername(&srp, username, usernameSize);
    wc_SrpSetParams(&srp, N, sizeof(N), g, sizeof(g), salt, sizeof(salt));
    wc_SrpSetPassword(&srp, password, passwordSize)

    byte public[64];
    word32 publicSz = 0;

    if( wc_SrpGetPublic(&srp, public, &publicSz) != 0)
    {
        // 公開エフェメラル取得エラー
    }

    wc_SrpTerm(&srp);
    \endcode

    \sa wc_SrpSetPrivate
    \sa wc_SrpSetPassword
    \sa wc_SrpSetVerifier
*/
int wc_SrpGetPublic(Srp* srp, byte* pub, word32* size);

/*!
    \ingroup SRP

    \brief セッション鍵を計算します。鍵は成功後にsrp->keyでアクセスできます。

    \return 0 成功
    \return BAD_FUNC_ARG srp、clientPubKey、またはserverPubKeyがnullの場合、またはclientPubKeySzまたはserverPubKeySzが0の場合に返されます。
    \return SRP_CALL_ORDER_E wc_SrpComputeKeyが順序外で呼び出された場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param clientPubKey クライアントの公開エフェメラル値。
    \param clientPubKeySz クライアントの公開エフェメラル値のサイズ。
    \param serverPubKey サーバーの公開エフェメラル値。
    \param serverPubKeySz サーバーの公開エフェメラル値のサイズ。

    _Example_
    \code
    Srp server;

    byte username[] = "user";
        word32 usernameSize = 4;
    byte password[] = "password";
    word32 passwordSize = 8;
    byte N[] = { }; // バイト配列Nの内容
    byte g[] = { }; // バイト配列gの内容
    byte salt[] = { }; // バイト配列saltの内容
    byte verifier[] = { }; // 何らかの検証子の内容
    byte serverPubKey[] = { }; // サーバー公開鍵の内容
    word32 serverPubKeySize = sizeof(serverPubKey);
    byte clientPubKey[64];
    word32 clientPubKeySize = 64;

    wc_SrpInit(&server, SRP_TYPE_SHA, SRP_SERVER_SIDE);
    wc_SrpSetUsername(&server, username, usernameSize);
    wc_SrpSetParams(&server, N, sizeof(N), g, sizeof(g), salt, sizeof(salt));
    wc_SrpSetVerifier(&server, verifier, sizeof(verifier));
    wc_SrpGetPublic(&server, serverPubKey, &serverPubKeySize);

    wc_SrpComputeKey(&server, clientPubKey, clientPubKeySz,
                                          serverPubKey, serverPubKeySize)
    wc_SrpTerm(&server);
    \endcode

    \sa wc_SrpGetPublic
*/
int wc_SrpComputeKey(Srp* srp,
                                 byte* clientPubKey, word32 clientPubKeySz,
                                 byte* serverPubKey, word32 serverPubKeySz);

/*!
    \ingroup SRP

    \brief 証明を取得します。この関数はwc_SrpComputeKeyの後に呼び出す必要があります。

    \return 0 成功
    \return BAD_FUNC_ARG srp、proof、またはsizeがnullの場合に返されます。
    \return BUFFER_E sizeがsrp->typeのハッシュサイズより小さい場合に返されます。
    \return <0 エラー

    \param srp Srp構造体。
    \param proof ピアの証明。
    \param size 証明のサイズ(バイト単位)。

    _Example_
    \code
    Srp cli;
    byte clientProof[SRP_MAX_DIGEST_SIZE];
    word32 clientProofSz = SRP_MAX_DIGEST_SIZE;

    // 前の例のステップに従ってSrpを初期化

    if (wc_SrpGetProof(&cli, clientProof, &clientProofSz) != 0)
    {
        // 証明取得エラー
    }
    \endcode

    \sa wc_SrpComputeKey
*/
int wc_SrpGetProof(Srp* srp, byte* proof, word32* size);

/*!
    \ingroup SRP

    \brief ピアの証明を検証します。この関数はwc_SrpGetSessionKeyの前に呼び出す必要があります。

    \return 0 成功
    \return <0 エラー

    \param srp Srp構造体。
    \param proof ピアの証明。
    \param size 証明のサイズ(バイト単位)。

    _Example_
    \code
    Srp cli;
    Srp srv;
    byte clientProof[SRP_MAX_DIGEST_SIZE];
    word32 clientProofSz = SRP_MAX_DIGEST_SIZE;

    // 前の例のステップに従ってSrpを初期化
    // 最初に証明を取得
    wc_SrpGetProof(&cli, clientProof, &clientProofSz)

    if (wc_SrpVerifyPeersProof(&srv, clientProof, clientProofSz) != 0)
    {
        // 証明検証エラー
    }
    \endcode

    \sa wc_SrpGetSessionKey
    \sa wc_SrpGetProof
    \sa wc_SrpTerm
*/
int wc_SrpVerifyPeersProof(Srp* srp, byte* proof, word32 size);
