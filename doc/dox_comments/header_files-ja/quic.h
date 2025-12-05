/*!
    \ingroup QUIC

    \brief ハンドシェイク中にシークレットが生成されたときに呼び出されるコールバック。
    QUICプロトコルハンドラはパケットの暗号化/復号を実行するため、early_data/handshake/applicationレベルのネゴシエートされたシークレットが必要です。

    このコールバックはハンドシェイク中に数回呼び出されます。読み取りまたは書き込みシークレットの両方、または一方のみが提供される場合があります。これは、与えられた暗号化レベルがすでに有効になっていることを意味するものではありません。

    \return 1 成功時、0 失敗時。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param level - シークレットが対応する暗号化レベル。
    \param read_secret - 与えられたレベルでの復号に使用されるシークレット、NULLの場合があります。
    \param write_secret - 与えられたレベルでの暗号化に使用されるシークレット、NULLの場合があります。
    \param secret_len - シークレットの長さ。

    \sa wolfSSL_set_quic_method
*/
int (*set_encryption_secrets)(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *read_secret,
                              const uint8_t *write_secret, size_t secret_len);

/*!
    \ingroup QUIC

    \brief ハンドシェイクCRYPTOデータをピアに転送するために呼び出されるコールバック。
    この方法で転送されるデータは暗号化されていません。これを行うのはQUICプロトコル実装の役割です。使用するシークレットは、指定された暗号化レベルによって決定されます。

    このコールバックは、ハンドシェイクまたはポストハンドシェイク処理中に数回呼び出される場合があります。データは完全なCRYPTOレコードをカバーする場合もありますが、部分的な場合もあります。ただし、別の暗号化レベルを使用する前に、コールバックはすべてのレコードデータを受信します。

    \return 1 成功時、0 失敗時。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param level - データの暗号化に使用する暗号化レベル。
    \param data - データ自体。
    \param len - データの長さ。

    \sa wolfSSL_set_quic_method
*/
int (*add_handshake_data)(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                          const uint8_t *data, size_t len);

/*!
    \ingroup QUIC

    \brief 送信するデータのアドバイザリーフラッシュのために呼び出されるコールバック。

    \return 1 成功時、0 失敗時。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_set_quic_method
*/
int (*flush_flight)(WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief 処理中にSSLアラートが発生したときに呼び出されるコールバック。

    \return 1 成功時、0 失敗時。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param level - アラートが発生したときに有効だった暗号化レベル。
    \param alert - エラー。

    \sa wolfSSL_set_quic_method
*/
int (*send_alert)(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, uint8_t alert);

/*!
    \ingroup QUIC

    \brief 必要な4つのコールバックを提供することにより、WOLFSSL_CTXおよびすべての派生WOLFSSLインスタンスに対してQUICプロトコルを有効化します。CTXはTLSv1.3である必要があります。

    渡されたquic_methodは、SSLインスタンスよりも長い寿命を持つ必要があります。コピーされません。すべてのコールバックを提供する必要があります。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ctx - wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param quic_method - コールバック構造体。

    \sa wolfSSL_is_quic
    \sa wolfSSL_set_quic_method
*/
int wolfSSL_CTX_set_quic_method(WOLFSSL_CTX *ctx, const WOLFSSL_QUIC_METHOD *quic_method);

/*!
    \ingroup QUIC

    \brief 必要な4つのコールバックを提供することにより、WOLFSSLインスタンスに対してQUICプロトコルを有効化します。WOLFSSLはTLSv1.3である必要があります。

    渡されたquic_methodは、SSLインスタンスよりも長い寿命を持つ必要があります。コピーされません。すべてのコールバックを提供する必要があります。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param quic_method - コールバック構造体。

    \sa wolfSSL_is_quic
    \sa wolfSSL_CTX_set_quic_method
*/
int wolfSSL_set_quic_method(WOLFSSL *ssl, const WOLFSSL_QUIC_METHOD *quic_method);

/*!
    \ingroup QUIC

    \brief WOLFSSLインスタンスでQUICが有効化されているかどうかを確認します。

    \return 1 WOLFSSLがQUICを使用している場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_CTX_quic_method
    \sa wolfSSL_CTX_set_quic_method
*/
int wolfSSL_is_quic(WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief 現在使用中の読み取り用の暗号化レベルを決定します。WOLFSSLインスタンスがQUICを使用している場合にのみ意味があります。

    有効なレベルは、データをやり取りする際に常にパラメータです。ピアからのデータは、この関数で報告されるレベル以外のレベルで到着する可能性があります。

    \return 暗号化レベル。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_quic_write_level
*/
WOLFSSL_ENCRYPTION_LEVEL wolfSSL_quic_read_level(const WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief 現在使用中の書き込み用の暗号化レベルを決定します。WOLFSSLインスタンスがQUICを使用している場合にのみ意味があります。

    有効なレベルは、データをやり取りする際に常にパラメータです。ピアからのデータは、この関数で報告されるレベル以外のレベルで到着する可能性があります。

    \return 暗号化レベル。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_quic_read_level
*/
WOLFSSL_ENCRYPTION_LEVEL wolfSSL_quic_write_level(const WOLFSSL *ssl);


/*!
    \ingroup QUIC

    \brief 使用するQUICバージョンを設定します。これを呼び出さない場合、WOLFSSLは両方（draft-27とv1）をサーバーに提供し、またはクライアントから両方を受け入れて最新のものをネゴシエートします。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param use_legacy - draft-27を使用する場合はtrue、QUICv1のみを使用する場合は0。

    \sa wolfSSL_set_quic_transport_version
*/
void wolfSSL_set_quic_use_legacy_codepoint(WOLFSSL *ssl, int use_legacy);

/*!
    \ingroup QUIC

    \brief 使用するQUICバージョンを設定します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param version - QUICバージョンに定義されたTLS拡張。

    \sa wolfSSL_set_quic_use_legacy_codepoint
*/
void wolfSSL_set_quic_transport_version(WOLFSSL *ssl, int version);

/*!
    \ingroup QUIC

    \brief 設定されたQUICバージョンを取得します。

    \return 設定されたバージョンのTLS拡張。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_set_quic_use_legacy_codepoint
    \sa wolfSSL_set_quic_transport_version
*/
int wolfSSL_get_quic_transport_version(const WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief 使用するQUICトランスポートパラメータを設定します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param params - 使用するパラメータバイト。
    \param params_len - パラメータの長さ。

    \sa wolfSSL_set_quic_use_legacy_codepoint
    \sa wolfSSL_set_quic_transport_version
*/
int wolfSSL_set_quic_transport_params(WOLFSSL *ssl, const uint8_t *params, size_t params_len);

/*!
    \ingroup QUIC

    \brief ネゴシエートされたQUICトランスポートバージョンを取得します。これは、ピアからの該当するTLS拡張が確認された後に呼び出された場合にのみ意味のある結果を提供します。

    \return ネゴシエートされたバージョンまたは-1。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_set_quic_use_legacy_codepoint
    \sa wolfSSL_set_quic_transport_version
*/
int wolfSSL_get_peer_quic_transport_version(const WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief ネゴシエートされたQUICトランスポートパラメータを取得します。これは、ピアからの該当するTLS拡張が確認された後に呼び出された場合にのみ意味のある結果を提供します。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param out_params - ピアによって送信されたパラメータ、利用できない場合はNULLに設定されます。
    \param out_params_len - ピアによって送信されたパラメータの長さ、利用できない場合は0に設定されます。

    \sa wolfSSL_get_peer_quic_transport_version
*/
void wolfSSL_get_peer_quic_transport_params(const WOLFSSL *ssl, const uint8_t **out_params, size_t *out_params_len);


/*!
    \ingroup QUIC

    \brief Early Dataが有効かどうかを設定します。サーバーがクライアントにこれを通知することを目的としています。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param enabled - early dataが有効な場合は!= 0。

*/
void wolfSSL_set_quic_early_data_enabled(WOLFSSL *ssl, int enabled);

/*!
    \ingroup QUIC

    \brief 与えられた暗号化レベルで「インフライト」であるべき、つまり未確認であるべきデータの量についてのアドバイスを取得します。これは、WOLFSSLインスタンスがバッファリングする準備ができているデータの量です。

    \return 推奨される最大インフライトデータ。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param level - 問い合わせる暗号化レベル。

*/
size_t wolfSSL_quic_max_handshake_flight_len(const WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level);


/*!
    \ingroup QUIC

    \brief 復号されたCRYPTOデータをWOLFSSLインスタンスに渡してさらに処理します。
    呼び出し間の暗号化レベルは増加することのみが許可され、暗号化レベルの変更が受け入れられる前にデータレコードが完全であることもチェックされます。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param level - データが暗号化されていたレベル。
    \param data - データ自体。
    \param len - データの長さ。

    \sa wolfSSL_process_quic_post_handshake
    \sa wolfSSL_quic_read_write
    \sa wolfSSL_accept
    \sa wolfSSL_connect
*/
int wolfSSL_provide_quic_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, const uint8_t *data, size_t len);

/*!
    \ingroup QUIC

    \brief ハンドシェイクが完了した後に提供されたCRYPTOレコードを処理します。それ以前に呼び出された場合は失敗します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_provide_quic_data
    \sa wolfSSL_quic_read_write
    \sa wolfSSL_accept
    \sa wolfSSL_connect
*/
WOLFSSL_API int wolfSSL_process_quic_post_handshake(WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief ハンドシェイク中またはハンドシェイク後に提供されたCRYPTOレコードを処理します。
    ハンドシェイクがまだ完了していない場合はハンドシェイクを進行させ、そうでない場合はwolfSSL_process_quic_post_handshake()のように動作します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_provide_quic_data
    \sa wolfSSL_quic_read_write
    \sa wolfSSL_accept
    \sa wolfSSL_connect
*/
int wolfSSL_quic_read_write(WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief TLSハンドシェイクでネゴシエートされたAEAD暗号を取得します。

    \return ネゴシエートされた暗号、または決定されていない場合はNULL。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_quic_aead_is_gcm
    \sa wolfSSL_quic_aead_is_ccm
    \sa wolfSSL_quic_aead_is_chacha20
    \sa wolfSSL_quic_get_aead_tag_len
    \sa wolfSSL_quic_get_md
    \sa wolfSSL_quic_get_hp
    \sa wolfSSL_quic_crypt_new
    \sa wolfSSL_quic_aead_encrypt
    \sa wolfSSL_quic_aead_decrypt
*/
const WOLFSSL_EVP_CIPHER *wolfSSL_quic_get_aead(WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief AEAD暗号がGCMであるかどうかを確認します。

    \return AEAD暗号がGCMの場合は!= 0。

    \param cipher - 暗号。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_aead_is_ccm
    \sa wolfSSL_quic_aead_is_chacha20
    \sa wolfSSL_quic_get_aead_tag_len
    \sa wolfSSL_quic_get_md
    \sa wolfSSL_quic_get_hp
    \sa wolfSSL_quic_crypt_new
    \sa wolfSSL_quic_aead_encrypt
    \sa wolfSSL_quic_aead_decrypt
*/
int wolfSSL_quic_aead_is_gcm(const WOLFSSL_EVP_CIPHER *aead_cipher);

/*!
    \ingroup QUIC

    \brief AEAD暗号がCCMであるかどうかを確認します。

    \return AEAD暗号がCCMの場合は!= 0。

    \param cipher - 暗号。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_aead_is_gcm
    \sa wolfSSL_quic_aead_is_chacha20
    \sa wolfSSL_quic_get_aead_tag_len
    \sa wolfSSL_quic_get_md
    \sa wolfSSL_quic_get_hp
    \sa wolfSSL_quic_crypt_new
    \sa wolfSSL_quic_aead_encrypt
    \sa wolfSSL_quic_aead_decrypt
*/
int wolfSSL_quic_aead_is_ccm(const WOLFSSL_EVP_CIPHER *aead_cipher);

/*!
    \ingroup QUIC

    \brief AEAD暗号がCHACHA20であるかどうかを確認します。

    \return AEAD暗号がCHACHA20の場合は!= 0。

    \param cipher - 暗号。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_aead_is_ccm
    \sa wolfSSL_quic_aead_is_gcm
    \sa wolfSSL_quic_get_aead_tag_len
    \sa wolfSSL_quic_get_md
    \sa wolfSSL_quic_get_hp
    \sa wolfSSL_quic_crypt_new
    \sa wolfSSL_quic_aead_encrypt
    \sa wolfSSL_quic_aead_decrypt
*/
int wolfSSL_quic_aead_is_chacha20(const WOLFSSL_EVP_CIPHER *aead_cipher);

/*!
    \ingroup QUIC

    \brief AEAD暗号のタグ長を決定します。

    \return AEAD暗号のタグ長。

    \param cipher - 暗号。

    \sa wolfSSL_quic_get_aead
*/
WOLFSSL_API size_t wolfSSL_quic_get_aead_tag_len(const WOLFSSL_EVP_CIPHER *aead_cipher);

/*!
    \ingroup QUIC

    \brief TLSハンドシェイクでネゴシエートされたメッセージダイジェストを決定します。

    \return TLSハンドシェイクでネゴシエートされたメッセージダイジェスト。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_get_hp
*/
WOLFSSL_API const WOLFSSL_EVP_MD *wolfSSL_quic_get_md(WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief TLSハンドシェイクでネゴシエートされたヘッダー保護暗号を決定します。

    \return TLSハンドシェイクでネゴシエートされたヘッダー保護暗号。

    \param ssl - wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_get_md
*/
const WOLFSSL_EVP_CIPHER *wolfSSL_quic_get_hp(WOLFSSL *ssl);

/*!
    \ingroup QUIC

    \brief 暗号化/復号用の暗号コンテキストを作成します。

    \return 作成されたコンテキスト、またはエラーの場合はNULL。

    \param cipher - コンテキストで使用する暗号。
    \param key - コンテキストで使用する鍵。
    \param iv - コンテキストで使用するiv。
    \param encrypt - 暗号化の場合は!= 0、そうでない場合は復号。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_get_hp
    \sa wolfSSL_quic_aead_encrypt
    \sa wolfSSL_quic_aead_decrypt
*/
WOLFSSL_EVP_CIPHER_CTX *wolfSSL_quic_crypt_new(const WOLFSSL_EVP_CIPHER *cipher,
                                               const uint8_t *key, const uint8_t *iv, int encrypt);

/*!
    \ingroup QUIC

    \brief 与えられたコンテキストで平文を暗号化します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param dest - 暗号化されたデータを書き込む宛先。
    \param aead_ctx - 使用する暗号コンテキスト。
    \param plain - 暗号化する平文データ。
    \param plainlen - 平文データの長さ。
    \param iv - 使用するiv。
    \param aad - 使用するaad。
    \param aadlen - aadの長さ。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_get_hp
    \sa wolfSSL_quic_crypt_new
    \sa wolfSSL_quic_aead_decrypt
*/
int wolfSSL_quic_aead_encrypt(uint8_t *dest, WOLFSSL_EVP_CIPHER_CTX *aead_ctx,
                              const uint8_t *plain, size_t plainlen,
                              const uint8_t *iv, const uint8_t *aad, size_t aadlen);

/*!
    \ingroup QUIC

    \brief 与えられたコンテキストで暗号文を復号します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param dest - 平文を書き込む宛先。
    \param ctx - 使用する暗号コンテキスト。
    \param enc - 復号する暗号化データ。
    \param envlen - 暗号化データの長さ。
    \param iv - 使用するiv。
    \param aad - 使用するaad。
    \param aadlen - aadの長さ。

    \sa wolfSSL_quic_get_aead
    \sa wolfSSL_quic_get_hp
    \sa wolfSSL_quic_crypt_new
    \sa wolfSSL_quic_aead_encrypt
*/
int wolfSSL_quic_aead_decrypt(uint8_t *dest, WOLFSSL_EVP_CIPHER_CTX *ctx,
                              const uint8_t *enc, size_t enclen,
                              const uint8_t *iv, const uint8_t *aad, size_t aadlen);

/*!
    \ingroup QUIC

    \brief 疑似ランダム鍵を抽出します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param dest - 鍵を書き込む宛先。
    \param md - 使用するメッセージダイジェスト。
    \param secret - 使用するシークレット。
    \param secretlen - シークレットの長さ。
    \param salt - 使用するソルト。
    \param saltlen - ソルトの長さ。

    \sa wolfSSL_quic_hkdf_expand
    \sa wolfSSL_quic_hkdf
*/
int wolfSSL_quic_hkdf_extract(uint8_t *dest, const WOLFSSL_EVP_MD *md,
                              const uint8_t *secret, size_t secretlen,
                              const uint8_t *salt, size_t saltlen);

/*!
    \ingroup QUIC

    \brief 疑似ランダム鍵を新しい鍵に拡張します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param dest - 鍵を書き込む宛先。
    \param destlen - 拡張する鍵の長さ。
    \param md - 使用するメッセージダイジェスト。
    \param secret - 使用するシークレット。
    \param secretlen - シークレットの長さ。
    \param info - 使用する情報。
    \param infolen - 情報の長さ。

    \sa wolfSSL_quic_hkdf_extract
    \sa wolfSSL_quic_hkdf
*/
int wolfSSL_quic_hkdf_expand(uint8_t *dest, size_t destlen,
                             const WOLFSSL_EVP_MD *md,
                             const uint8_t *secret, size_t secretlen,
                             const uint8_t *info, size_t infolen);

/*!
    \ingroup QUIC

    \brief 疑似ランダム鍵を拡張および抽出します。

    \return WOLFSSL_SUCCESS 成功した場合。

    \param dest - 鍵を書き込む宛先。
    \param destlen - 鍵の長さ。
    \param md - 使用するメッセージダイジェスト。
    \param secret - 使用するシークレット。
    \param secretlen - シークレットの長さ。
    \param salt - 使用するソルト。
    \param saltlen - ソルトの長さ。
    \param info - 使用する情報。
    \param infolen - 情報の長さ。

    \sa wolfSSL_quic_hkdf_extract
    \sa wolfSSL_quic_hkdf_expand
*/
int wolfSSL_quic_hkdf(uint8_t *dest, size_t destlen,
                      const WOLFSSL_EVP_MD *md,
                      const uint8_t *secret, size_t secretlen,
                      const uint8_t *salt, size_t saltlen,
                      const uint8_t *info, size_t infolen);
