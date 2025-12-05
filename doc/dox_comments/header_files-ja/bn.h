/*!
    \ingroup openSSL

    \brief この関数は次の数学演算を実行します "r = (a^p) % m"。

    \return SSL_SUCCESS 数学演算が正常に実行された場合。
    \return SSL_FAILURE エラーケースが発生した場合。

    \param r 結果を保持する構造体。
    \param a 累乗される値。
    \param p aを累乗する指数。
    \param m 使用する剰余。
    \param ctx 現在wolfSSLでは使用されていないため、NULLにできます。

    _Example_
    \code
    WOLFSSL_BIGNUM r,a,p,m;
    int ret;
    // big number値を設定
    ret  = wolfSSL_BN_mod_exp(r, a, p, m, NULL);
    // ret値を確認
    \endcode

    \sa wolfSSL_BN_new
    \sa wolfSSL_BN_free
*/
int wolfSSL_BN_mod_exp(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
        const WOLFSSL_BIGNUM *p, const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx);
