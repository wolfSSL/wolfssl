/*!
    \ingroup Curve25519

    \brief この関数は、与えられた乱数生成器rngを使用して、与えられたサイズ（keysize）のCurve25519鍵を生成し、与えられたcurve25519_key構造体に格納します。wc_curve25519_init()を通じて鍵構造体が初期化された後に呼び出す必要があります。

    \return 0 鍵の生成に成功し、与えられたcurve25519_key構造体に格納された場合に返されます。
    \return ECC_BAD_ARG_E 入力keysizeがcurve25519鍵のkeysizeに対応していない場合（32バイト）に返されます。
    \return RNG_FAILURE_E rng内部ステータスがDRBG_OKでない場合、またはrngで次のランダムブロックを生成する際にエラーがある場合に返されます。
    \return BAD_FUNC_ARG 渡された入力パラメータのいずれかがNULLの場合に返されます。

    \param [in] rng ecc鍵を生成するために使用されるRNGオブジェクトへのポインタ。
    \param [in] keysize 生成する鍵のサイズ。curve25519では32バイトである必要があります。
    \param [in,out] key 生成された鍵を格納するcurve25519_key構造体へのポインタ。

    _Example_
    \code
    int ret;

    curve25519_key key;
    wc_curve25519_init(&key); // 鍵を初期化
    WC_RNG rng;
    wc_InitRng(&rng); // 乱数生成器を初期化

    ret = wc_curve25519_make_key(&rng, 32, &key);
    if (ret != 0) {
        // Curve25519鍵作成エラー
    }
    \endcode

    \sa wc_curve25519_init
*/

int wc_curve25519_make_key(WC_RNG* rng, int keysize, curve25519_key* key);

/*!
    \ingroup Curve25519

    \brief この関数は、秘密の秘密鍵と受信した公開鍵を与えられた共有秘密鍵を計算します。生成された秘密鍵をバッファoutに格納し、秘密鍵の変数をoutlenに割り当てます。ビッグエンディアンのみをサポートします。

    \return 0 共有秘密鍵の計算に成功した場合に返されます。
    \return BAD_FUNC_ARG 渡された入力パラメータのいずれかがNULLの場合に返されます。
    \return ECC_BAD_ARG_E 実装フィンガープリントを回避するために、公開鍵の最初のビットが設定されている場合に返されます。

    \param [in] private_key ユーザーの秘密鍵で初期化されたcurve25519_key構造体へのポインタ。
    \param [in] public_key 受信した公開鍵を含むcurve25519_key構造体へのポインタ。
    \param [out] out 32バイトの計算された秘密鍵を格納するバッファへのポインタ。
    \param [in,out] outlen 出力バッファに書き込まれた長さを格納するポインタ。

    _Example_
    \code
    int ret;

    byte sharedKey[32];
    word32 keySz;
    curve25519_key privKey, pubKey;
    // 両方の鍵を初期化

    ret = wc_curve25519_shared_secret(&privKey, &pubKey, sharedKey, &keySz);
    if (ret != 0) {
        // 共有鍵生成エラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
    \sa wc_curve25519_shared_secret_ex
*/

int wc_curve25519_shared_secret(curve25519_key* private_key,
                                curve25519_key* public_key,
                                byte* out, word32* outlen);

/*!
    \ingroup Curve25519

    \brief この関数は、秘密の秘密鍵と受信した公開鍵を与えられた共有秘密鍵を計算します。生成された秘密鍵をバッファoutに格納し、秘密鍵の変数をoutlenに割り当てます。ビッグエンディアンとリトルエンディアンの両方をサポートします。

    \return 0 共有秘密鍵の計算に成功した場合に返されます。
    \return BAD_FUNC_ARG 渡された入力パラメータのいずれかがNULLの場合に返されます。
    \return ECC_BAD_ARG_E 実装フィンガープリントを回避するために、公開鍵の最初のビットが設定されている場合に返されます。

    \param [in] private_key ユーザーの秘密鍵で初期化されたcurve25519_key構造体へのポインタ。
    \param [in] public_key 受信した公開鍵を含むcurve25519_key構造体へのポインタ。
    \param [out] out 32バイトの計算された秘密鍵を格納するバッファへのポインタ。
    \param [in,out] outlen 出力バッファに書き込まれた長さを格納するポインタ。
    \param [in] endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;

    byte sharedKey[32];
    word32 keySz;

    curve25519_key privKey, pubKey;
    // 両方の鍵を初期化

    ret = wc_curve25519_shared_secret_ex(&privKey, &pubKey, sharedKey, &keySz,
             EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 共有鍵生成エラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
    \sa wc_curve25519_shared_secret
*/

int wc_curve25519_shared_secret_ex(curve25519_key* private_key,
                                   curve25519_key* public_key,
                                   byte* out, word32* outlen, int endian);

/*!
    \ingroup Curve25519

    \brief この関数はCurve25519鍵を初期化します。構造体の鍵を生成する前に呼び出す必要があります。

    \return 0 curve25519_key構造体の初期化に成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key 初期化するcurve25519_key構造体へのポインタ。

    _Example_
    \code
    curve25519_key key;
    wc_curve25519_init(&key); // 鍵を初期化
    // 鍵を作成し、暗号化に進む
    \endcode

    \sa wc_curve25519_make_key
*/

int wc_curve25519_init(curve25519_key* key);

/*!
    \ingroup Curve25519

    \brief この関数はCurve25519オブジェクトを解放します。

    \param [in,out] key 解放する鍵オブジェクトへのポインタ。

    _Example_
    \code
    curve25519_key privKey;
    // 鍵を初期化し、共有秘密鍵の生成に使用
    wc_curve25519_free(&privKey);
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
*/

void wc_curve25519_free(curve25519_key* key);

/*!
    \ingroup Curve25519

    \brief この関数はcurve25519秘密鍵のみをインポートします。（ビッグエンディアン）

    \return 0 秘密鍵のインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはprivがnullの場合に返されます。
    \return ECC_BAD_ARG_E privSzがCURVE25519_KEY_SIZEと等しくない場合に返されます。

    \param [in] priv インポートする秘密鍵を含むバッファへのポインタ。
    \param [in] privSz インポートする秘密鍵の長さ。
    \param [in,out] key インポートされた鍵を格納する構造体へのポインタ。

    _Example_
    \code
    int ret;

    byte priv[] = { // 秘密鍵の内容 };
    curve25519_key key;
    wc_curve25519_init(&key);

    ret = wc_curve25519_import_private(priv, sizeof(priv), &key);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_curve25519_import_private_ex
    \sa wc_curve25519_size
*/

int wc_curve25519_import_private(const byte* priv, word32 privSz,
                                 curve25519_key* key);

/*!
    \ingroup Curve25519

    \brief curve25519秘密鍵のみのインポート。（ビッグエンディアンまたはリトルエンディアン）

    \return 0 秘密鍵のインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはprivがnullの場合に返されます。
    \return ECC_BAD_ARG_E privSzがCURVE25519_KEY_SIZEと等しくない場合に返されます。

    \param [in] priv インポートする秘密鍵を含むバッファへのポインタ。
    \param [in] privSz インポートする秘密鍵の長さ。
    \param [in,out] key インポートされた鍵を格納する構造体へのポインタ。
    \param [in]  endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;

    byte priv[] = { // 秘密鍵の内容 };
    curve25519_key key;
    wc_curve25519_init(&key);

    ret = wc_curve25519_import_private_ex(priv, sizeof(priv), &key,
            EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 鍵のインポートエラー
    }

    \endcode

    \sa wc_curve25519_import_private
    \sa wc_curve25519_size
*/

int wc_curve25519_import_private_ex(const byte* priv, word32 privSz,
                                    curve25519_key* key, int endian);

/*!
    \ingroup Curve25519

    \brief この関数は、公開鍵-秘密鍵ペアをcurve25519_key構造体にインポートします。ビッグエンディアンのみ。

    \return 0 curve25519_key構造体へのインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがnullの場合に返されます。
    \return ECC_BAD_ARG_E 入力鍵の鍵サイズが公開鍵または秘密鍵のサイズと一致しない場合に返されます。

    \param [in] priv インポートする秘密鍵を含むバッファへのポインタ。
    \param [in] privSz インポートする秘密鍵の長さ。
    \param [in] pub インポートする公開鍵を含むバッファへのポインタ。
    \param [in] pubSz インポートする公開鍵の長さ。
    \param [in,out] key インポートされた鍵を格納する構造体へのポインタ。

    _Example_
    \code
    int ret;

    byte priv[32];
    byte pub[32];
    // 公開鍵と秘密鍵で初期化
    curve25519_key key;

    wc_curve25519_init(&key);
    // 鍵を初期化

    ret = wc_curve25519_import_private_raw(&priv, sizeof(priv), pub,
            sizeof(pub), &key);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
    \sa wc_curve25519_import_public
    \sa wc_curve25519_export_private_raw
*/

int wc_curve25519_import_private_raw(const byte* priv, word32 privSz,
                            const byte* pub, word32 pubSz, curve25519_key* key);

/*!
    \ingroup Curve25519

    \brief この関数は、公開鍵-秘密鍵ペアをcurve25519_key構造体にインポートします。ビッグエンディアンとリトルエンディアンの両方をサポートします。

    \return 0 curve25519_key構造体へのインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがnullの場合に返されます。
    \return ECC_BAD_ARG_E 入力鍵の鍵サイズが公開鍵または秘密鍵のサイズと一致しない場合に返されます。

    \param [in] priv インポートする秘密鍵を含むバッファへのポインタ。
    \param [in] privSz インポートする秘密鍵の長さ。
    \param [in] pub インポートする公開鍵を含むバッファへのポインタ。
    \param [in] pubSz インポートする公開鍵の長さ。
    \param [in,out] key インポートされた鍵を格納する構造体へのポインタ。
    \param [in] endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;
    byte priv[32];
    byte pub[32];
    // 公開鍵と秘密鍵で初期化
    curve25519_key key;

    wc_curve25519_init(&key);
    // 鍵を初期化

    ret = wc_curve25519_import_private_raw_ex(&priv, sizeof(priv), pub,
            sizeof(pub), &key, EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
    \sa wc_curve25519_import_public
    \sa wc_curve25519_export_private_raw
    \sa wc_curve25519_import_private_raw
*/

int wc_curve25519_import_private_raw_ex(const byte* priv, word32 privSz,
                                        const byte* pub, word32 pubSz,
                                        curve25519_key* key, int endian);


/*!
    \ingroup Curve25519

    \brief この関数は、curve25519_key構造体から秘密鍵をエクスポートし、与えられたoutバッファに格納します。また、outLenをエクスポートされた鍵のサイズに設定します。ビッグエンディアンのみ。

    \return 0 curve25519_key構造体から秘密鍵のエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。
    \return ECC_BAD_ARG_E wc_curve25519_size()がkeyと等しくない場合に返されます。

    \param [in] key 鍵をエクスポートする構造体へのポインタ。
    \param [out] out エクスポートされた鍵を格納するバッファへのポインタ。
    \param [in,out] outLen 入力時は、outのバイト単位のサイズ。
    出力時は、出力バッファに書き込まれたバイト数を格納します。

    _Example_
    \code
    int ret;
    byte priv[32];
    int privSz;

    curve25519_key key;
    // 鍵を初期化して作成

    ret = wc_curve25519_export_private_raw(&key, priv, &privSz);
    if (ret != 0) {
        // 鍵のエクスポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
    \sa wc_curve25519_import_private_raw
    \sa wc_curve25519_export_private_raw_ex
*/

int wc_curve25519_export_private_raw(curve25519_key* key, byte* out,
                                     word32* outLen);

/*!
    \ingroup Curve25519

    \brief この関数は、curve25519_key構造体から秘密鍵をエクスポートし、与えられたoutバッファに格納します。また、outLenをエクスポートされた鍵のサイズに設定します。ビッグエンディアンまたはリトルエンディアンを指定できます。

    \return 0 curve25519_key構造体から秘密鍵のエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。
    \return ECC_BAD_ARG_E wc_curve25519_size()がkeyと等しくない場合に返されます。

    \param [in] key 鍵をエクスポートする構造体へのポインタ。
    \param [out] out エクスポートされた鍵を格納するバッファへのポインタ。
    \param [in,out] outLen 入力時は、outのバイト単位のサイズ。
    出力時は、出力バッファに書き込まれたバイト数を格納します。
    \param [in] endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;

    byte priv[32];
    int privSz;
    curve25519_key key;
    // 鍵を初期化して作成
    ret = wc_curve25519_export_private_raw_ex(&key, priv, &privSz,
            EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 鍵のエクスポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
    \sa wc_curve25519_import_private_raw
    \sa wc_curve25519_export_private_raw
    \sa wc_curve25519_size
*/

int wc_curve25519_export_private_raw_ex(curve25519_key* key, byte* out,
                                        word32* outLen, int endian);

/*!
    \ingroup Curve25519

    \brief この関数は、与えられたinバッファから公開鍵をインポートし、curve25519_key構造体に格納します。

    \return 0 curve25519_key構造体への公開鍵のインポートに成功した場合に返されます。
    \return ECC_BAD_ARG_E inLenパラメータが鍵構造体の鍵サイズと一致しない場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。

    \param [in] in インポートする公開鍵を含むバッファへのポインタ。
    \param [in] inLen インポートする公開鍵の長さ。
    \param [in,out] key 鍵を格納するcurve25519_key構造体へのポインタ。

    _Example_
    \code
    int ret;

    byte pub[32];
    // pubを公開鍵で初期化

    curve25519_key key;
    // 鍵を初期化

    ret = wc_curve25519_import_public(pub,sizeof(pub), &key);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_export_public
    \sa wc_curve25519_import_private_raw
    \sa wc_curve25519_import_public_ex
    \sa wc_curve25519_check_public
    \sa wc_curve25519_size
*/

int wc_curve25519_import_public(const byte* in, word32 inLen,
                                curve25519_key* key);

/*!
    \ingroup Curve25519

    \brief この関数は、与えられたinバッファから公開鍵をインポートし、curve25519_key構造体に格納します。

    \return 0 curve25519_key構造体への公開鍵のインポートに成功した場合に返されます。
    \return ECC_BAD_ARG_E inLenパラメータが鍵構造体の鍵サイズと一致しない場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。

    \param [in] in インポートする公開鍵を含むバッファへのポインタ。
    \param [in] inLen インポートする公開鍵の長さ。
    \param [in,out] key 鍵を格納するcurve25519_key構造体へのポインタ。
    \param [in] endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;

    byte pub[32];
    // pubを公開鍵で初期化
    curve25519_key key;
    // 鍵を初期化

    ret = wc_curve25519_import_public_ex(pub, sizeof(pub), &key,
            EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_export_public
    \sa wc_curve25519_import_private_raw
    \sa wc_curve25519_import_public
    \sa wc_curve25519_check_public
    \sa wc_curve25519_size
*/

int wc_curve25519_import_public_ex(const byte* in, word32 inLen,
                                   curve25519_key* key, int endian);

/*!
    \ingroup Curve25519

    \brief この関数は、エンディアン順序を考慮して、公開鍵バッファが有効なCurve25519鍵値を保持しているかどうかをチェックします。

    \return 0 公開鍵の値が有効な場合に返されます。
    \return ECC_BAD_ARG_E 公開鍵の値が有効でない場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。

    \param [in] pub チェックする公開鍵を含むバッファへのポインタ。
    \param [in] pubLen チェックする公開鍵の長さ。
    \param [in] endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;

    byte pub[] = { // 公開鍵の内容 };

    ret = wc_curve25519_check_public_ex(pub, sizeof(pub), EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_import_public
    \sa wc_curve25519_import_public_ex
    \sa wc_curve25519_size
*/

int wc_curve25519_check_public(const byte* pub, word32 pubSz, int endian);

/*!
    \ingroup Curve25519

    \brief この関数は、与えられた鍵構造体から公開鍵をエクスポートし、結果をoutバッファに格納します。ビッグエンディアンのみ。

    \return 0 curve25519_key構造体から公開鍵のエクスポートに成功した場合に返されます。
    \return ECC_BAD_ARG_E outLenがCURVE25519_PUB_KEY_SIZEより小さい場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。

    \param [in] key 鍵をエクスポートするcurve25519_key構造体へのポインタ。
    \param [out] out 公開鍵を格納するバッファへのポインタ。
    \param [in,out] outLen 入力時は、outのバイト単位のサイズ。
    出力時は、出力バッファに書き込まれたバイト数を格納します。

    _Example_
    \code
    int ret;

    byte pub[32];
    int pubSz;

    curve25519_key key;
    // 鍵を初期化して作成
    ret = wc_curve25519_export_public(&key, pub, &pubSz);
    if (ret != 0) {
        // 鍵のエクスポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_export_private_raw
    \sa wc_curve25519_import_public
*/

int wc_curve25519_export_public(curve25519_key* key, byte* out, word32* outLen);

/*!
    \ingroup Curve25519

    \brief この関数は、与えられた鍵構造体から公開鍵をエクスポートし、結果をoutバッファに格納します。ビッグエンディアンとリトルエンディアンの両方をサポートします。

    \return 0 curve25519_key構造体から公開鍵のエクスポートに成功した場合に返されます。
    \return ECC_BAD_ARG_E outLenがCURVE25519_PUB_KEY_SIZEより小さい場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。

    \param [in] key 鍵をエクスポートするcurve25519_key構造体へのポインタ。
    \param [out] out 公開鍵を格納するバッファへのポインタ。
    \param [in,out] outLen 入力時は、outのバイト単位のサイズ。
    出力時は、出力バッファに書き込まれたバイト数を格納します。
    \param [in] endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;

    byte pub[32];
    int pubSz;

    curve25519_key key;
    // 鍵を初期化して作成

    ret = wc_curve25519_export_public_ex(&key, pub, &pubSz, EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 鍵のエクスポートエラー
    }
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_export_private_raw
    \sa wc_curve25519_import_public
*/

int wc_curve25519_export_public_ex(curve25519_key* key, byte* out,
                                   word32* outLen, int endian);

/*!
    \ingroup Curve25519

    \brief Curve25519鍵ペアをエクスポートします。ビッグエンディアンのみ。

    \return 0 curve25519_key構造体から鍵ペアのエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。
    \return ECC_BAD_ARG_E privSzがCURVE25519_KEY_SIZEより小さい、またはpubSzがCURVE25519_PUB_KEY_SIZEより小さい場合に返されます。

    \param [in] key 鍵ペアをエクスポートするcurve448_key構造体へのポインタ。
    \param [out] priv 秘密鍵を格納するバッファへのポインタ。
    \param [in,out] privSz 入力時は、privバッファのバイト単位のサイズ。
    出力時は、privバッファに書き込まれたバイト数を格納します。
    \param [out] pub 公開鍵を格納するバッファへのポインタ。
    \param [in,out] pubSz 入力時は、pubバッファのバイト単位のサイズ。
    出力時は、pubバッファに書き込まれたバイト数を格納します。

    _Example_
    \code
    int ret;

    byte pub[32];
    byte priv[32];
    int pubSz;
    int privSz;

    curve25519_key key;
    // 鍵を初期化して作成

    ret = wc_curve25519_export_key_raw(&key, priv, &privSz, pub, &pubSz);
    if (ret != 0) {
        // 鍵のエクスポートエラー
    }
    \endcode

    \sa wc_curve25519_export_key_raw_ex
    \sa wc_curve25519_export_private_raw
*/

int wc_curve25519_export_key_raw(curve25519_key* key,
                                 byte* priv, word32 *privSz,
                                 byte* pub, word32 *pubSz);

/*!
    \ingroup Curve25519

    \brief curve25519鍵ペアをエクスポートします。ビッグエンディアンまたはリトルエンディアン。

    \return 0 curve25519_key構造体から鍵ペアのエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLの場合に返されます。
    \return ECC_BAD_ARG_E privSzがCURVE25519_KEY_SIZEより小さい、またはpubSzがCURVE25519_PUB_KEY_SIZEより小さい場合に返されます。

    \param [in] key 鍵ペアをエクスポートするcurve448_key構造体へのポインタ。
    \param [out] priv 秘密鍵を格納するバッファへのポインタ。
    \param [in,out] privSz 入力時は、privバッファのバイト単位のサイズ。
    出力時は、privバッファに書き込まれたバイト数を格納します。
    \param [out] pub 公開鍵を格納するバッファへのポインタ。
    \param [in,out] pubSz 入力時は、pubバッファのバイト単位のサイズ。
    出力時は、pubバッファに書き込まれたバイト数を格納します。
    \param [in] endian 使用する形式を設定するためのEC25519_BIG_ENDIANまたはEC25519_LITTLE_ENDIAN。

    _Example_
    \code
    int ret;

    byte pub[32];
    byte priv[32];
    int pubSz;
    int privSz;

    curve25519_key key;
    // 鍵を初期化して作成

    ret = wc_curve25519_export_key_raw_ex(&key,priv, &privSz, pub, &pubSz,
            EC25519_BIG_ENDIAN);
    if (ret != 0) {
        // 鍵のエクスポートエラー
    }
    \endcode

    \sa wc_curve25519_export_key_raw
    \sa wc_curve25519_export_private_raw_ex
    \sa wc_curve25519_export_public_ex
*/

int wc_curve25519_export_key_raw_ex(curve25519_key* key,
                                    byte* priv, word32 *privSz,
                                    byte* pub, word32 *pubSz,
                                    int endian);

/*!
    \ingroup Curve25519

    \brief この関数は、与えられた鍵構造体の鍵サイズを返します。

    \return Success 有効で初期化されたcurve25519_key構造体が与えられた場合、鍵のサイズを返します。
    \return 0 keyがNULLの場合に返されます。

    \param [in] key 鍵サイズを決定するcurve25519_key構造体へのポインタ。

    _Example_
    \code
    int keySz;

    curve25519_key key;
    // 鍵を初期化して作成

    keySz = wc_curve25519_size(&key);
    \endcode

    \sa wc_curve25519_init
    \sa wc_curve25519_make_key
*/

int wc_curve25519_size(curve25519_key* key);