/*!
    \ingroup openSSL

    \brief この関数は、WOLFSSL_BIO構造体にキーをPEM形式で書き込みます。

    \return SSL_SUCCESS 成功時。
    \return SSL_FAILURE 失敗時。

    \param bio PEMバッファを取得するWOLFSSL_BIO構造体。
    \param key PEM形式に変換するキー。
    \param cipher EVP暗号構造体。
    \param passwd パスワード。
    \param len パスワードの長さ。
    \param cb パスワードコールバック。
    \param arg オプション引数。

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_EVP_PKEY* key;
    int ret;
    // bioを作成してキーをセットアップ
    ret = wolfSSL_PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    //ret値を確認
    \endcode

    \sa wolfSSL_PEM_read_bio_X509_AUX
*/

int wolfSSL_PEM_write_bio_PrivateKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int len,
                                        wc_pem_password_cb* cb, void* arg);
