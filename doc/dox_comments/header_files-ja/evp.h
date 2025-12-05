/*!
    \ingroup openSSL

    \brief それぞれのWOLFSSL_EVP_CIPHERポインタのゲッター関数。これらの暗号文字列を設定するには、まずプログラムでwolfSSL_EVP_init()を一度呼び出す必要があります。wolfSSL_EVP_des_ede3_ecb()の場合、WOLFSSL_DES_ECBマクロが定義されている必要があります。

    \return pointer DES EDE3操作用のWOLFSSL_EVP_CIPHERポインタを返します。

    \param none パラメータなし。

    _Example_
    \code
    printf("block size des ede3 cbc = %d\n",
    wolfSSL_EVP_CIPHER_block_size(wolfSSL_EVP_des_ede3_cbc()));
    printf("block size des ede3 ecb = %d\n",
    wolfSSL_EVP_CIPHER_block_size(wolfSSL_EVP_des_ede3_ecb()));
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_init
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ede3_ecb(void);

/*!
    \ingroup openSSL

    \brief それぞれのWOLFSSL_EVP_CIPHERポインタのゲッター関数。これらの暗号文字列を設定するには、まずプログラムでwolfSSL_EVP_init()を一度呼び出す必要があります。wolfSSL_EVP_des_ecb()の場合、WOLFSSL_DES_ECBマクロが定義されている必要があります。

    \return pointer DES操作用のWOLFSSL_EVP_CIPHERポインタを返します。

    \param none パラメータなし。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER* cipher;
    cipher = wolfSSL_EVP_des_cbc();
    …
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_init
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_cbc(void);

/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_MD_CTXを初期化する関数。この関数は、wolfSSLがWOLFSSL_ENGINEを使用しないため、wolfSSL_EVP_DigestInit()のラッパーです。

    \return SSL_SUCCESS 正常に設定された場合。
    \return SSL_FAILURE 成功しなかった場合。

    \param ctx 初期化する構造体。
    \param type 実行するハッシュのタイプ、例えばSHA。
    \param impl 使用するエンジン。wolfSSLでは該当なし、NULLでも可。

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* md = NULL;
    wolfCrypt_Init();
    md = wolfSSL_EVP_MD_CTX_new();
    if (md == NULL) {
        printf("error setting md\n");
        return -1;
    }
    printf("cipher md init ret = %d\n", wolfSSL_EVP_DigestInit_ex(md,
    wolfSSL_EVP_sha1(), e));
    //リソースを解放
    \endcode

    \sa wolfSSL_EVP_MD_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_MD_CTX_free
*/
int wolfSSL_EVP_DigestInit_ex(WOLFSSL_EVP_MD_CTX* ctx,
                                     const WOLFSSL_EVP_MD* type,
                                     WOLFSSL_ENGINE *impl);

/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_CIPHER_CTXを初期化する関数。この関数は、wolfSSLがWOLFSSL_ENGINEを使用しないため、wolfSSL_CipherInit()のラッパーです。

    \return SSL_SUCCESS 正常に設定された場合。
    \return SSL_FAILURE 成功しなかった場合。

    \param ctx 初期化する構造体。
    \param type 実行する暗号化/復号のタイプ、例えばAES。
    \param impl 使用するエンジン。wolfSSLでは該当なし、NULLでも可。
    \param key 設定する鍵。
    \param iv アルゴリズムが必要とする場合のiv。
    \param enc 暗号化(1)または復号(0)フラグ。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    WOLFSSL_ENGINE* e = NULL;
    unsigned char key[16];
    unsigned char iv[12];
    wolfCrypt_Init();
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("issue creating ctx\n");
        return -1;
    }

    printf("cipher init ex error ret = %d\n", wolfSSL_EVP_CipherInit_ex(NULL,
    EVP_aes_128_    cbc(), e, key, iv, 1));
    printf("cipher init ex success ret = %d\n", wolfSSL_EVP_CipherInit_ex(ctx,
    EVP_aes_128_c    bc(), e, key, iv, 1));
    // リソースを解放
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int  wolfSSL_EVP_CipherInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    WOLFSSL_ENGINE *impl,
                                    const unsigned char* key,
                                    const unsigned char* iv,
                                    int enc);

/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_CIPHER_CTXを初期化する関数。この関数は、wolfSSLがWOLFSSL_ENGINEを使用しないため、wolfSSL_EVP_CipherInit()のラッパーです。暗号化フラグを暗号化に設定します。

    \return SSL_SUCCESS 正常に設定された場合。
    \return SSL_FAILURE 成功しなかった場合。

    \param ctx 初期化する構造体。
    \param type 実行する暗号化のタイプ、例えばAES。
    \param impl 使用するエンジン。wolfSSLでは該当なし、NULLでも可。
    \param key 使用する鍵。
    \param iv 使用するiv。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    wolfCrypt_Init();
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("error setting ctx\n");
        return -1;
    }
    printf("cipher ctx init ret = %d\n", wolfSSL_EVP_EncryptInit_ex(ctx,
    wolfSSL_EVP_aes_128_cbc(), e, key, iv));
    //リソースを解放
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int  wolfSSL_EVP_EncryptInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    WOLFSSL_ENGINE *impl,
                                    const unsigned char* key,
                                    const unsigned char* iv);

/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_CIPHER_CTXを初期化する関数。この関数は、wolfSSLがWOLFSSL_ENGINEを使用しないため、wolfSSL_EVP_CipherInit()のラッパーです。暗号化フラグを復号に設定します。

    \return SSL_SUCCESS 正常に設定された場合。
    \return SSL_FAILURE 成功しなかった場合。

    \param ctx 初期化する構造体。
    \param type 実行する暗号化/復号のタイプ、例えばAES。
    \param impl 使用するエンジン。wolfSSLでは該当なし、NULLでも可。
    \param key 設定する鍵。
    \param iv アルゴリズムが必要とする場合のiv。
    \param enc 暗号化(1)または復号(0)フラグ。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    WOLFSSL_ENGINE* e = NULL;
    unsigned char key[16];
    unsigned char iv[12];

    wolfCrypt_Init();

    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("issue creating ctx\n");
        return -1;
    }

    printf("cipher init ex error ret = %d\n", wolfSSL_EVP_DecryptInit_ex(NULL,
    EVP_aes_128_    cbc(), e, key, iv, 1));
    printf("cipher init ex success ret = %d\n", wolfSSL_EVP_DecryptInit_ex(ctx,
    EVP_aes_128_c    bc(), e, key, iv, 1));
    // リソースを解放
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int  wolfSSL_EVP_DecryptInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    WOLFSSL_ENGINE *impl,
                                    const unsigned char* key,
                                    const unsigned char* iv);

/*!
    \ingroup openSSL

    \brief データを暗号化/復号する関数。inバッファが暗号化または復号される対象として追加され、outバッファが結果を保持します。outlは暗号化/復号された情報の長さになります。

    \return SSL_SUCCESS 成功した場合。
    \return SSL_FAILURE 成功しなかった場合。

    \param ctx 暗号タイプを取得する構造体。
    \param out 出力を保持するバッファ。
    \param outl 出力のサイズに調整されます。
    \param in 操作を実行するバッファ。
    \param inl 入力バッファの長さ。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    unsigned char out[100];
    int outl;
    unsigned char in[100];
    int inl = 100;

    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    // ctxをセットアップ
    ret = wolfSSL_EVP_CipherUpdate(ctx, out, outl, in, inl);
    // ret値をチェック
    // バッファoutはoutlバイトのデータを保持
    // リソースを解放
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int wolfSSL_EVP_CipherUpdate(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl,
                                   const unsigned char *in, int inl);

/*!
    \ingroup openSSL

    \brief この関数は、パディングを追加する最終暗号操作を実行します。WOLFSSL_EVP_CIPHER_CTX構造体にWOLFSSL_EVP_CIPH_NO_PADDINGフラグが設定されている場合、1が返され、暗号化/復号は実行されません。パディングフラグが設定されている場合、ctxが暗号化に設定されているときにパディングが追加され暗号化され、復号に設定されているときにパディング値がチェックされます。

    \return 1 成功時に返されます。
    \return 0 失敗が発生した場合。

    \param ctx 復号/暗号化に使用する構造体。
    \param out 最終復号/暗号化用のバッファ。
    \param out1 関数によってデータが追加されたときのoutバッファのサイズ。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int out1;
    unsigned char out[64];
    // ctxを作成
    wolfSSL_EVP_CipherFinal(ctx, out, &out1);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
int  wolfSSL_EVP_CipherFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);

/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_CIPHER_CTX構造体の鍵長のセッター関数。

    \return SSL_SUCCESS 正常に設定された場合。
    \return SSL_FAILURE 鍵長の設定に失敗した場合。

    \param ctx 鍵長を設定する構造体。
    \param keylen 鍵の長さ。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int keylen;
    // ctxを作成
    wolfSSL_EVP_CIPHER_CTX_set_key_length(ctx, keylen);
    \endcode

    \sa wolfSSL_EVP_CIPHER_flags
*/
int  wolfSSL_EVP_CIPHER_CTX_set_key_length(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                                     int keylen);

/*!
    \ingroup openSSL

    \brief これはctxブロックサイズのゲッター関数です。

    \return size ctx->block_sizeを返します。

    \param ctx ブロックサイズを取得する暗号ctx。

    _Example_
    \code
    const WOLFSSL_CVP_CIPHER_CTX* ctx;
    //ctxをセットアップ
    printf("block size = %d\n", wolfSSL_EVP_CIPHER_CTX_block_size(ctx));
    \endcode

    \sa wolfSSL_EVP_CIPHER_block_size
*/
int wolfSSL_EVP_CIPHER_CTX_block_size(const WOLFSSL_EVP_CIPHER_CTX *ctx);

/*!
    \ingroup openSSL

    \brief これは暗号のブロックサイズのゲッター関数です。

    \return size ブロックサイズを返します。

    \param cipher ブロックサイズを取得する暗号。

    _Example_
    \code
    printf("block size = %d\n",
    wolfSSL_EVP_CIPHER_block_size(wolfSSL_EVP_aes_256_ecb()));
    \endcode

    \sa wolfSSL_EVP_aes_256_ctr
*/
int wolfSSL_EVP_CIPHER_block_size(const WOLFSSL_EVP_CIPHER *cipher);

/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_CIPHER_CTX構造体のセッター関数。

    \return none 戻り値なし。

    \param ctx フラグを設定する構造体。
    \param flag 構造体に設定するフラグ。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int flag;
    // ctxを作成
    wolfSSL_EVP_CIPHER_CTX_set_flags(ctx, flag);
    \endcode

    \sa wolfSSL_EVP_CIPHER_flags
    \sa wolfSSL_EVP_CIPHER_CTX_flags
*/
void wolfSSL_EVP_CIPHER_CTX_set_flags(WOLFSSL_EVP_CIPHER_CTX *ctx, int flags);

/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_CIPHER_CTX構造体のクリア関数。

    \return none 戻り値なし。

    \param ctx フラグをクリアする構造体。
    \param flag 構造体でクリアするフラグ値。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int flag;
    // ctxを作成
    wolfSSL_EVP_CIPHER_CTX_clear_flags(ctx, flag);
    \endcode

    \sa wolfSSL_EVP_CIPHER_flags
    \sa wolfSSL_EVP_CIPHER_CTX_flags
*/
void wolfSSL_EVP_CIPHER_CTX_clear_flags(WOLFSSL_EVP_CIPHER_CTX *ctx, int flags);

/*!
    \ingroup openSSL

    \brief パディングを使用するためのWOLFSSL_EVP_CIPHER_CTX構造体のセッター関数。

    \return SSL_SUCCESS 正常に設定された場合。
    \return BAD_FUNC_ARG null引数が渡された場合。

    \param ctx パディングフラグを設定する構造体。
    \param padding パディングを設定しない場合は0、パディングを設定する場合は1。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    // ctxを作成
    wolfSSL_EVP_CIPHER_CTX_set_padding(ctx, 1);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
int  wolfSSL_EVP_CIPHER_CTX_set_padding(WOLFSSL_EVP_CIPHER_CTX *c, int pad);


/*!
    \ingroup openSSL

    \brief WOLFSSL_EVP_CIPHER_CTX構造体のゲッター関数。v1.1.0で非推奨

    \return unsigned long フラグ/モードのunsigned long。

    \param ctx フラグを取得する構造体。

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    unsigned long flags;
    ctx = wolfSSL_EVP_CIPHER_CTX_new()
    flags = wolfSSL_EVP_CIPHER_CTX_flags(ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfSSL_EVP_CIPHER_flags
*/
unsigned long wolfSSL_EVP_CIPHER_CTX_flags(const WOLFSSL_EVP_CIPHER_CTX *ctx);
