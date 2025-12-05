/*!
    \ingroup IoTSafe
    \brief この関数は、指定されたコンテキストでIoT-Safeサポートを有効にします。

    \param ctx IoT-safeサポートを有効にする必要があるWOLFSSL_CTXオブジェクトへのポインタ
    \return 0 成功時
    \return WC_HW_E ハードウェアエラー時

    _Example_
    \code
    WOLFSSL_CTX *ctx;
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx)
        return NULL;
    wolfSSL_CTX_iotsafe_enable(ctx);
    \endcode

    \sa wolfSSL_iotsafe_on
    \sa wolfIoTSafe_SetCSIM_read_cb
    \sa wolfIoTSafe_SetCSIM_write_cb
*/
int wolfSSL_CTX_iotsafe_enable(WOLFSSL_CTX *ctx);


/*!
    \ingroup IoTSafe
    \brief この関数は、IoT-Safe TLSコールバックを指定されたSSLセッションに接続します。
    \brief これは、スロットのIDが1バイト長の場合にSSLセッションをIoT-Safeアプレットに接続するために呼び出す必要があります。
           IoT-SAFEスロットのIDが2バイト以上の場合は、代わりに\ref wolfSSL_iotsafe_on_ex "wolfSSL_iotsafe_on_ex()"を使用する必要があります。

    \param ssl コールバックが有効になるWOLFSSLオブジェクトへのポインタ
    \param privkey_id ホストの秘密鍵を含むiot-safeアプレットスロットのID
    \param ecdh_keypair_slot ECDH鍵ペアを格納するiot-safeアプレットスロットのID
    \param peer_pubkey_slot ECDH用に他のエンドポイントの公開鍵を格納するiot-safeアプレットスロットのID
    \param peer_cert_slot 検証用に他のエンドポイントの公開鍵を格納するiot-safeアプレットスロットのID
    \return 0 成功時
    \return NOT_COMPILED_IN HAVE_PK_CALLBACKSが無効な場合
    \return BAD_FUNC_ARG sslポインタが無効な場合

    _Example_
    \code
    // IoT-Safe用の鍵IDを定義
    #define PRIVKEY_ID 0x02
    #define ECDH_KEYPAIR_ID 0x03
    #define PEER_PUBKEY_ID 0x04
    #define PEER_CERT_ID 0x05
    // 新しいsslセッションを作成
    WOLFSSL *ssl;
    ssl = wolfSSL_new(ctx);
    if (!ssl)
        return NULL;
    // IoT-Safeを有効にして鍵スロットを関連付け
    ret = wolfSSL_CTX_iotsafe_enable(ctx);
    if (ret == 0) {
        ret = wolfSSL_iotsafe_on(ssl, PRIVKEY_ID, ECDH_KEYPAIR_ID, PEER_PUBKEY_ID, PEER_CERT_ID);
    }
    \endcode

    \sa wolfSSL_iotsafe_on_ex
    \sa wolfSSL_CTX_iotsafe_enable
*/
int wolfSSL_iotsafe_on(WOLFSSL *ssl, byte privkey_id,
       byte ecdh_keypair_slot, byte peer_pubkey_slot, byte peer_cert_slot);


/*!
    \ingroup IoTSafe
    \brief この関数は、IoT-Safe TLSコールバックを指定されたSSLセッションに接続します。
           これは\ref wolfSSL_iotsafe_on "wolfSSL_iotsafe_on"と同等ですが、IoT-SAFEスロットのIDを参照渡しでき、IDフィールドの長さをパラメータ"id_size"で指定できる点が異なります。


    \param ssl コールバックが有効になるWOLFSSLオブジェクトへのポインタ
    \param privkey_id ホストの秘密鍵を含むiot-safeアプレットスロットのIDへのポインタ
    \param ecdh_keypair_slot ECDH鍵ペアを格納するiot-safeアプレットスロットのIDへのポインタ
    \param peer_pubkey_slot ECDH用に他のエンドポイントの公開鍵を格納するiot-safeアプレットスロットのIDへのポインタ
    \param peer_cert_slot 検証用に他のエンドポイントの公開鍵を格納するiot-safeアプレットスロットのIDへのポインタ
    \param id_size 各スロットIDのサイズ
    \return 0 成功時
    \return NOT_COMPILED_IN HAVE_PK_CALLBACKSが無効な場合
    \return BAD_FUNC_ARG sslポインタが無効な場合

    _Example_
    \code
    // IoT-Safe用の鍵IDを定義(16ビット、リトルエンディアン)
    #define PRIVKEY_ID 0x0201
    #define ECDH_KEYPAIR_ID 0x0301
    #define PEER_PUBKEY_ID 0x0401
    #define PEER_CERT_ID 0x0501
    #define ID_SIZE (sizeof(word16))

    word16 privkey = PRIVKEY_ID,
             ecdh_keypair = ECDH_KEYPAIR_ID,
             peer_pubkey = PEER_PUBKEY_ID,
             peer_cert = PEER_CERT_ID;



    // 新しいsslセッションを作成
    WOLFSSL *ssl;
    ssl = wolfSSL_new(ctx);
    if (!ssl)
        return NULL;
    // IoT-Safeを有効にして鍵スロットを関連付け
    ret = wolfSSL_CTX_iotsafe_enable(ctx);
    if (ret == 0) {
        ret = wolfSSL_CTX_iotsafe_on_ex(ssl, &privkey, &ecdh_keypair, &peer_pubkey, &peer_cert, ID_SIZE);
    }
    \endcode

    \sa wolfSSL_iotsafe_on
    \sa wolfSSL_CTX_iotsafe_enable
*/
int wolfSSL_iotsafe_on_ex(WOLFSSL *ssl, byte *privkey_id,
       byte *ecdh_keypair_slot, byte *peer_pubkey_slot, byte *peer_cert_slot, word16 id_size);


/*!
    \ingroup IoTSafe
    \brief AT+CSIMコマンド用の読み取りコールバックを関連付けます。この入力関数は通常、モデムと通信するUARTチャネルの読み取りイベントに関連付けられます。関連付けられる読み取りコールバックはグローバルで、同時にIoT-safeサポートを使用するすべてのコンテキストに対して変更されます。
    \param rf UART読み取りイベントに関連付けられる読み取りコールバック。コールバック関数は2つの引数(buf、len)を受け取り、lenまで読み取られた文字数を返します。改行文字に遭遇すると、コールバックはこれまでに受信した文字数(改行文字を含む)を返す必要があります。

    _Example_
    \code

    // USART読み取り関数、他の場所で定義
    int usart_read(char *buf, int len);

    wolfIoTSafe_SetCSIM_read_cb(usart_read);

    \endcode

    \sa wolfIoTSafe_SetCSIM_write_cb
*/
void wolfIoTSafe_SetCSIM_read_cb(wolfSSL_IOTSafe_CSIM_read_cb rf);

/*!
    \ingroup IoTSafe
    \brief AT+CSIMコマンド用の書き込みコールバックを関連付けます。この出力関数は通常、モデムと通信するUARTチャネルの書き込みイベントに関連付けられます。関連付けられる書き込みコールバックはグローバルで、同時にIoT-safeサポートを使用するすべてのコンテキストに対して変更されます。
    \param rf UART書き込みイベントに関連付けられる書き込みコールバック。コールバック関数は2つの引数(buf、len)を受け取り、lenまで書き込まれた文字数を返します。

    _Example_
    \code
    // USART書き込み関数、他の場所で定義
    int usart_write(const char *buf, int len);
    wolfIoTSafe_SetCSIM_write_cb(usart_write);
    \endcode

    \sa wolfIoTSafe_SetCSIM_read_cb
*/
void wolfIoTSafe_SetCSIM_write_cb(wolfSSL_IOTSafe_CSIM_write_cb wf);



/*!
    \ingroup IoTSafe
    \brief IoT-Safe関数GetRandomを使用して、指定されたサイズのランダムバッファを生成します。この関数はwolfCrypt RNGオブジェクトによって自動的に使用されます。

    \param out ランダムなバイトシーケンスが格納されるバッファ。
    \param sz 生成するランダムシーケンスのサイズ(バイト単位)
    \return 0 成功時

*/
int wolfIoTSafe_GetRandom(unsigned char* out, word32 sz);


/*!
    \ingroup IoTSafe
    \brief IoT-Safeアプレット上のファイルに保存されている証明書をインポートし、メモリ内にローカルに保存します。1バイトのファイルIDフィールドで動作します。

    \param id 証明書が保存されているIoT-Safeアプレット内のファイルID
    \param output 証明書がインポートされるバッファ
    \param sz バッファoutputで利用可能な最大サイズ
    \return インポートされた証明書の長さ
    \return < 0 失敗の場合

    _Example_
    \code
    #define CRT_CLIENT_FILE_ID 0x03
    unsigned char cert_buffer[2048];
    // 証明書をバッファに取得
    cert_buffer_size = wolfIoTSafe_GetCert(CRT_CLIENT_FILE_ID, cert_buffer, 2048);
    if (cert_buffer_size < 1) {
        printf("Bad cli cert\n");
        return -1;
    }
    printf("Loaded Client certificate from IoT-Safe, size = %lu\n", cert_buffer_size);

    // TLSクライアントコンテキストのアイデンティティとして証明書バッファを使用
    if (wolfSSL_CTX_use_certificate_buffer(cli_ctx, cert_buffer,
                cert_buffer_size, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        printf("Cannot load client cert\n");
        return -1;
    }
    printf("Client certificate successfully imported.\n");
    \endcode

*/
int wolfIoTSafe_GetCert(byte id, unsigned char *output, unsigned long sz);

/*!
    \ingroup IoTSafe
    \brief IoT-Safeアプレット上のファイルに保存されている証明書をインポートし、メモリ内にローカルに保存します。\ref wolfIoTSafe_GetCert "wolfIoTSafe_GetCert"と同等ですが、2バイト以上のファイルIDで呼び出すことができます。

    \param id 証明書が保存されているIoT-Safeアプレット内のファイルIDへのポインタ
    \param id_sz ファイルIDのサイズ
    \param output 証明書がインポートされるバッファ
    \param sz バッファoutputで利用可能な最大サイズ
    \return インポートされた証明書の長さ
    \return < 0 失敗の場合

    _Example_
    \code

    \endcode

*/
int wolfIoTSafe_GetCert_ex(uint8_t *id, uint16_t id_sz, unsigned char *output, unsigned long sz);

/*!
    \ingroup IoTSafe
    \brief IoT-Safeアプレットに保存されているECC 256ビット公開鍵をecc_keyオブジェクトにインポートします。

    \param key IoT-Safeアプレットからインポートされた鍵を含むecc_keyオブジェクト
    \param id 公開鍵が保存されているIoT-Safeアプレット内の鍵ID
    \return 0 成功時
    \return < 0 失敗の場合


    \sa wc_iotsafe_ecc_export_public
    \sa wc_iotsafe_ecc_export_private

*/
int wc_iotsafe_ecc_import_public(ecc_key *key, byte key_id);

/*!
    \ingroup IoTSafe
    \brief ECC 256ビット公開鍵をecc_keyオブジェクトからIoT-Safeアプレット内の書き込み可能な公開鍵スロットにエクスポートします。
    \param key エクスポートする鍵を含むecc_keyオブジェクト
    \param id 公開鍵が保存されるIoT-Safeアプレット内の鍵ID
    \return 0 成功時
    \return < 0 失敗の場合


    \sa wc_iotsafe_ecc_import_public_ex
    \sa wc_iotsafe_ecc_export_private

*/
int wc_iotsafe_ecc_export_public(ecc_key *key, byte key_id);


/*!
    \ingroup IoTSafe
    \brief ECC 256ビット公開鍵をecc_keyオブジェクトからIoT-Safeアプレット内の書き込み可能な公開鍵スロットにエクスポートします。
           \ref wc_iotsafe_ecc_import_public "wc_iotsafe_ecc_import_public"と同等ですが、2バイト以上の鍵IDで呼び出すことができます。
    \param key エクスポートする鍵を含むecc_keyオブジェクト
    \param id 公開鍵が保存されるIoT-Safeアプレット内の鍵IDへのポインタ
    \param id_size 鍵IDのサイズ

    \return 0 成功時
    \return < 0 失敗の場合


    \sa wc_iotsafe_ecc_import_public
    \sa wc_iotsafe_ecc_export_private

*/
int wc_iotsafe_ecc_import_public_ex(ecc_key *key, byte *key_id, word16 id_size);

/*!
    \ingroup IoTSafe
    \brief ECC 256ビット鍵をecc_keyオブジェクトからIoT-Safeアプレット内の書き込み可能な秘密鍵スロットにエクスポートします。
    \param key エクスポートする鍵を含むecc_keyオブジェクト
    \param id 秘密鍵が保存されるIoT-Safeアプレット内の鍵ID
    \return 0 成功時
    \return < 0 失敗の場合


    \sa wc_iotsafe_ecc_export_private_ex
    \sa wc_iotsafe_ecc_import_public
    \sa wc_iotsafe_ecc_export_public

*/
int wc_iotsafe_ecc_export_private(ecc_key *key, byte key_id);

/*!
    \ingroup IoTSafe
    \brief ECC 256ビット鍵をecc_keyオブジェクトからIoT-Safeアプレット内の書き込み可能な秘密鍵スロットにエクスポートします。
           \ref wc_iotsafe_ecc_export_private "wc_iotsafe_ecc_export_private"と同等ですが、2バイト以上の鍵IDで呼び出すことができます。

    \param key エクスポートする鍵を含むecc_keyオブジェクト
    \param id 秘密鍵が保存されるIoT-Safeアプレット内の鍵IDへのポインタ
    \param id_size 鍵IDのサイズ
    \return 0 成功時
    \return < 0 失敗の場合


    \sa wc_iotsafe_ecc_export_private
    \sa wc_iotsafe_ecc_import_public
    \sa wc_iotsafe_ecc_export_public

*/
int wc_iotsafe_ecc_export_private_ex(ecc_key *key, byte *key_id, word16 id_size);

/*!
    \ingroup IoTSafe
    \brief IoT-Safeアプレット内に事前に保存または事前プロビジョニングされた秘密鍵を使用して、事前計算されたハッシュに署名します。

    \param in 署名するメッセージハッシュを含むバッファへのポインタ
    \param inlen 署名するメッセージハッシュの長さ
    \param out 生成された署名を格納するバッファ
    \param outlen 出力バッファの最大長。メッセージ署名の生成に成功すると、outに書き込まれたバイト数を格納します
    \param id ペイロードに署名する秘密鍵を含むスロットのIoT-Safeアプレット内の鍵ID
    \return 0 成功時
    \return < 0 失敗の場合

    \sa wc_iotsafe_ecc_sign_hash_ex
    \sa wc_iotsafe_ecc_verify_hash
    \sa wc_iotsafe_ecc_gen_k

*/
int wc_iotsafe_ecc_sign_hash(byte *in, word32 inlen, byte *out, word32 *outlen, byte key_id);

/*!
    \ingroup IoTSafe
    \brief IoT-Safeアプレット内に事前に保存または事前プロビジョニングされた秘密鍵を使用して、事前計算されたハッシュに署名します。\ref wc_iotsafe_ecc_sign_hash "wc_iotsafe_ecc_sign_hash"と同等ですが、2バイト以上の鍵IDで呼び出すことができます。

    \param in 署名するメッセージハッシュを含むバッファへのポインタ
    \param inlen 署名するメッセージハッシュの長さ
    \param out 生成された署名を格納するバッファ
    \param outlen 出力バッファの最大長。メッセージ署名の生成に成功すると、outに書き込まれたバイト数を格納します
    \param id ペイロードに署名する秘密鍵を含むスロットのIoT-Safeアプレット内の鍵IDへのポインタ
    \param id_size 鍵IDのサイズ
    \return 0 成功時
    \return < 0 失敗の場合

    \sa wc_iotsafe_ecc_sign_hash
    \sa wc_iotsafe_ecc_verify_hash
    \sa wc_iotsafe_ecc_gen_k

*/
int wc_iotsafe_ecc_sign_hash_ex(byte *in, word32 inlen, byte *out, word32 *outlen, byte *key_id, word16 id_size);

/*!
    \ingroup IoTSafe
    \brief IoT-Safeアプレット内に事前に保存または事前プロビジョニングされた公開鍵を使用して、事前計算されたハッシュに対するECC署名を検証します。結果はresに書き込まれます。1は有効、0は無効です。
    注意: 有効性をテストするために戻り値を使用しないでください。resのみを使用してください。

    \return 0 成功時(署名が有効でない場合でも)
    \return < 0 失敗の場合。

    \param sig  検証する署名を含むバッファ
    \param hash 署名されたハッシュ(メッセージダイジェスト)
    \param hashlen ハッシュの長さ(オクテット)
    \param res 署名の結果、1==有効、0==無効
    \param key_id IoT-Safeアプレット内に公開ECC鍵が保存されているスロットのID

    \sa wc_iotsafe_ecc_verify_hash_ex
    \sa wc_iotsafe_ecc_sign_hash
    \sa wc_iotsafe_ecc_gen_k

*/
int wc_iotsafe_ecc_verify_hash(byte *sig, word32 siglen, byte *hash, word32 hashlen, int *res, byte key_id);

/*!
    \ingroup IoTSafe
    \brief IoT-Safeアプレット内に事前に保存または事前プロビジョニングされた公開鍵を使用して、事前計算されたハッシュに対するECC署名を検証します。結果はresに書き込まれます。1は有効、0は無効です。
    注意: 有効性をテストするために戻り値を使用しないでください。resのみを使用してください。
    \ref wc_iotsafe_ecc_verify_hash "wc_iotsafe_ecc_verify_hash"と同等ですが、2バイト以上の鍵IDで呼び出すことができます。

    \return 0 成功時(署名が有効でない場合でも)
    \return < 0 失敗の場合。

    \param sig  検証する署名を含むバッファ
    \param hash 署名されたハッシュ(メッセージダイジェスト)
    \param hashlen ハッシュの長さ(オクテット)
    \param res 署名の結果、1==有効、0==無効
    \param key_id IoT-Safeアプレット内に公開ECC鍵が保存されているスロットのID
    \param id_size 鍵IDのサイズ

    \sa wc_iotsafe_ecc_verify_hash
    \sa wc_iotsafe_ecc_sign_hash
    \sa wc_iotsafe_ecc_gen_k

*/
int wc_iotsafe_ecc_verify_hash_ex(byte *sig, word32 siglen, byte *hash, word32 hashlen, int *res, byte *key_id, word16 id_size);

/*!
    \ingroup IoTSafe
    \brief ECC 256ビット鍵ペアを生成し、IoT-Safeアプレット内の(書き込み可能な)スロットに保存します。
    \param key_id IoT-Safeアプレット内にECC鍵ペアが保存されているスロットのID。
    \return 0 成功時
    \return < 0 失敗の場合。

    \sa wc_iotsafe_ecc_gen_k_ex
    \sa wc_iotsafe_ecc_sign_hash
    \sa wc_iotsafe_ecc_verify_hash
*/
int wc_iotsafe_ecc_gen_k(byte key_id);

/*!
    \ingroup IoTSafe
    \brief ECC 256ビット鍵ペアを生成し、IoT-Safeアプレット内の(書き込み可能な)スロットに保存します。
           \ref wc_iotsafe_ecc_gen_k "wc_iotsafe_ecc_gen_k"と同等ですが、2バイト以上の鍵IDで呼び出すことができます。
    \param key_id IoT-Safeアプレット内にECC鍵ペアが保存されているスロットのID。
    \param id_size 鍵IDのサイズ
    \return 0 成功時
    \return < 0 失敗の場合。

    \sa wc_iotsafe_ecc_gen_k
    \sa wc_iotsafe_ecc_sign_hash_ex
    \sa wc_iotsafe_ecc_verify_hash_ex
*/
int wc_iotsafe_ecc_gen_k(byte key_id);
