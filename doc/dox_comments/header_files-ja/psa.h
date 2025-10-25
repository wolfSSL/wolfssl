/*!
    \ingroup PSA
    \brief この関数は、指定されたコンテキストでPSAサポートを有効にします。

    \param ctx PSAサポートを有効にする必要があるWOLFSSL_CTXオブジェクトへのポインタ
    \return WOLFSSL_SUCCESS 成功時
    \return BAD_FUNC_ARG ctx == NULLの場合

    _Example_
    \code
    WOLFSSL_CTX *ctx;
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx)
        return NULL;
    ret = wolfSSL_CTX_psa_enable(ctx);
    if (ret != WOLFSSL_SUCCESS)
        printf("can't enable PSA on ctx");

    \endcode

    \sa wolfSSL_set_psa_ctx
*/
int wolfSSL_CTX_psa_enable(WOLFSSL_CTX *ctx);

/*!
    \ingroup PSA

    \brief この関数は、指定されたSSLセッションのPSAコンテキストをセットアップします

    \param ssl ctxを有効にするWOLFSSLへのポインタ
    \param ctx struct psa_ssl_ctxへのポインタ(SSLセッションごとに一意である必要があります)

    \return WOLFSSL_SUCCESS 成功時
    \return BAD_FUNC_ARG sslまたはctxがNULLの場合

    この関数は、指定されたSSLセッションへのTLSコールバック用のPSAコンテキストをセットアップします。セッションの終了時に、コンテキストによって使用されたリソースは、wolfSSL_free_psa_ctx()を使用して解放する必要があります。

    _Example_
    \code
    // 新しいSSLセッションを作成
    WOLFSSL *ssl;
    struct psa_ssl_ctx psa_ctx = { 0 };
    ssl = wolfSSL_new(ctx);
    if (!ssl)
        return NULL;
    // PSAコンテキストをセットアップ
    ret = wolfSSL_set_psa_ctx(ssl, ctx);
    \endcode

    \sa wolfSSL_psa_set_private_key_id
    \sa wolfSSL_psa_free_psa_ctx
*/
int wolfSSL_set_psa_ctx(WOLFSSL *ssl, struct psa_ssl_ctx *ctx);

/*!
    \ingroup PSA
    \brief この関数は、PSAコンテキストによって使用されるリソースを解放します

    \param ctx struct psa_ssl_ctxへのポインタ

    \sa wolfSSL_set_psa_ctx
*/
void wolfSSL_free_psa_ctx(struct psa_ssl_ctx *ctx);

/*!
    \ingroup PSA
    \brief この関数は、SSLセッションで使用される秘密鍵を設定します

    \param ctx struct psa_ssl_ctxへのポインタ
    \param id 秘密鍵として使用されるキーのPSA ID

    _Example_
    \code
    // 新しいSSLセッションを作成
    WOLFSSL *ssl;
    struct psa_ssl_ctx psa_ctx = { 0 };
    psa_key_id_t key_id;

    // キープロビジョニングは既に完了
    get_private_key_id(&key_id);

    ssl = wolfSSL_new(ctx);
    if (!ssl)
        return NULL;

    wolfSSL_psa_set_private_key_id(&psa_ctx, key_id);
    wolfSSL_set_psa_ctx(ssl, ctx);
    \endcode

    \sa wolfSSL_set_psa_ctx
*/

int wolfSSL_psa_set_private_key_id(struct psa_ssl_ctx *ctx,
                                               psa_key_id_t id);