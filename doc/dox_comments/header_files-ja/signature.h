/*!
    \ingroup Signature

    \brief この関数は、結果の署名の最大サイズを返します。

    \return sig_typeがサポートされていない場合、SIG_TYPE_Eを返します。sig_typeが無効な場合、BAD_FUNC_ARGを返します。正の戻り値は、署名の最大サイズを示します。

    \param sig_type WC_SIGNATURE_TYPE_ECCやWC_SIGNATURE_TYPE_RSAなどの署名タイプの列挙値。
    \param key ecc_keyやRsaKeyなどのキー構造体へのポインタ。
    \param key_len キー構造体のサイズ。

    _Example_
    \code
    // 署名の長さを取得
    enum wc_SignatureType sig_type = WC_SIGNATURE_TYPE_ECC;
    ecc_key eccKey;
    word32 sigLen;
    wc_ecc_init(&eccKey);
    sigLen = wc_SignatureGetSize(sig_type, &eccKey, sizeof(eccKey));
    if (sigLen > 0) {
    	// 成功
    }
    \endcode

    \sa wc_HashGetDigestSize
    \sa wc_SignatureGenerate
    \sa wc_SignatureVerify
*/
int wc_SignatureGetSize(enum wc_SignatureType sig_type,
    const void* key, word32 key_len);

/*!
    \ingroup Signature

    \brief この関数は、データをハッシュ化し、結果のハッシュとキーを使用して署名を検証することで、署名を検証します。

    \return 0 成功
    \return SIG_TYPE_E -231、署名タイプが有効化されていない/利用できない
    \return BAD_FUNC_ARG -173、不正な関数引数が提供された
    \return BUFFER_E -132、出力バッファが小さすぎるか、入力が大きすぎる。

    \param hash_type "WC_HASH_TYPE_SHA256"などの"enum wc_HashType"からのハッシュタイプ。
    \param sig_type WC_SIGNATURE_TYPE_ECCやWC_SIGNATURE_TYPE_RSAなどの署名タイプの列挙値。
    \param data ハッシュ化するデータを含むバッファへのポインタ。
    \param data_len データバッファの長さ。
    \param sig 署名を出力するバッファへのポインタ。
    \param sig_len 署名出力バッファの長さ。
    \param key ecc_keyやRsaKeyなどのキー構造体へのポインタ。
    \param key_len キー構造体のサイズ。

    _Example_
    \code
    int ret;
    ecc_key eccKey;

    // 公開鍵をインポート
    wc_ecc_init(&eccKey);
    ret = wc_ecc_import_x963(eccPubKeyBuf, eccPubKeyLen, &eccKey);
    // 公開鍵を使用して署名検証を実行
    ret = wc_SignatureVerify(
    WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
    fileBuf, fileLen,
    sigBuf, sigLen,
    &eccKey, sizeof(eccKey));
    printf("署名検証: %s
    (%d)\n", (ret == 0) ? "合格" : "不合格", ret);
    wc_ecc_free(&eccKey);
    \endcode

    \sa wc_SignatureGetSize
    \sa wc_SignatureGenerate
*/
int wc_SignatureVerify(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    const byte* sig, word32 sig_len,
    const void* key, word32 key_len);

/*!
    \ingroup Signature

    \brief この関数は、キーを使用してデータから署名を生成します。最初にデータのハッシュを作成し、次にキーを使用してハッシュに署名します。

    \return 0 成功
    \return SIG_TYPE_E -231、署名タイプが有効化されていない/利用できない
    \return BAD_FUNC_ARG -173、不正な関数引数が提供された
    \return BUFFER_E -132、出力バッファが小さすぎるか、入力が大きすぎる。

    \param hash_type "WC_HASH_TYPE_SHA256"などの"enum wc_HashType"からのハッシュタイプ。
    \param sig_type WC_SIGNATURE_TYPE_ECCやWC_SIGNATURE_TYPE_RSAなどの署名タイプの列挙値。
    \param data ハッシュ化するデータを含むバッファへのポインタ。
    \param data_len データバッファの長さ。
    \param sig 署名を出力するバッファへのポインタ。
    \param sig_len 署名出力バッファの長さ。
    \param key ecc_keyやRsaKeyなどのキー構造体へのポインタ。
    \param key_len キー構造体のサイズ。
    \param rng 初期化されたRNG構造体へのポインタ。

    _Example_
    \code
    int ret;
    WC_RNG rng;
    ecc_key eccKey;

    wc_InitRng(&rng);
    wc_ecc_init(&eccKey);

    // キーを生成
    ret = wc_ecc_make_key(&rng, 32, &eccKey);

    // 署名の長さを取得してバッファを割り当て
    sigLen = wc_SignatureGetSize(sig_type, &eccKey, sizeof(eccKey));
    sigBuf = malloc(sigLen);

    // 公開鍵を使用して署名検証を実行
    ret = wc_SignatureGenerate(
        WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
        fileBuf, fileLen,
        sigBuf, &sigLen,
        &eccKey, sizeof(eccKey),
        &rng);
    printf("署名生成: %s
    (%d)\n", (ret == 0) ? "合格" : "不合格", ret);

    free(sigBuf);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_SignatureGetSize
    \sa wc_SignatureVerify
*/
int wc_SignatureGenerate(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    byte* sig, word32 *sig_len,
    const void* key, word32 key_len,
    WC_RNG* rng);
