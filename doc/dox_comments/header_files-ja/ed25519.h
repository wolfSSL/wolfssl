/*!
    \ingroup ED25519

    \brief この関数は、ed25519_keyオブジェクトに格納された秘密鍵からEd25519公開鍵を生成します。公開鍵をバッファpubKeyに格納します。

    \return 0 公開鍵の作成に成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはpubKeyがNULLと評価された場合、または指定されたキーサイズが32バイトでない場合に返されます（Ed25519は32バイトのキーを持ちます）。
    \return ECC_PRIV_KEY_E ed25519_keyオブジェクトに秘密鍵が含まれていない場合に返されます。
    \return MEMORY_E 関数実行中にメモリの割り当てエラーが発生した場合に返されます。

    \param [in] key キーを生成するed25519_keyへのポインタ。
    \param [out] pubKey 公開鍵を格納するバッファへのポインタ。
    \param [in] pubKeySz 公開鍵のサイズ。ED25519_PUB_KEY_SIZEである必要があります。

    _Example_
    \code
    int ret;

    ed25519_key key;
    byte priv[] = { 32バイトの秘密鍵で初期化 };
    byte pub[32];
    word32 pubSz = sizeof(pub);

    wc_ed25519_init(&key);
    wc_ed25519_import_private_only(priv, sizeof(priv), &key);
    ret = wc_ed25519_make_public(&key, pub, &pubSz);
    if (ret != 0) {
        // 公開鍵の作成エラー
    }
    \endcode

    \sa wc_ed25519_init
    \sa wc_ed25519_import_private_only
    \sa wc_ed25519_make_key
*/

int wc_ed25519_make_public(ed25519_key* key, unsigned char* pubKey,
                           word32 pubKeySz);

/*!
    \ingroup ED25519

    \brief この関数は新しいEd25519キーを生成し、それをkeyに格納します。

    \return 0 ed25519_keyの作成に成功した場合に返されます。
    \return BAD_FUNC_ARG rngまたはkeyがNULLと評価された場合、または指定されたキーサイズが32バイトでない場合に返されます（Ed25519は32バイトのキーを持ちます）。
    \return MEMORY_E 関数実行中にメモリの割り当てエラーが発生した場合に返されます。

    \param [in] rng キーを生成するために使用する初期化済みRNGオブジェクトへのポインタ。
    \param [in] keysize 生成するキーの長さ。Ed25519の場合は常に32である必要があります。
    \param [in,out] key キーを生成するed25519_keyへのポインタ。

    _Example_
    \code
    int ret;

    WC_RNG rng;
    ed25519_key key;

    wc_InitRng(&rng);
    wc_ed25519_init(&key);
    wc_ed25519_make_key(&rng, 32, &key);
    if (ret != 0) {
        // キー作成エラー
    }
    \endcode

    \sa wc_ed25519_init
*/

int wc_ed25519_make_key(WC_RNG* rng, int keysize, ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにed25519_keyオブジェクトを使用してメッセージに署名します。

    \return 0 メッセージの署名の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、または出力バッファが生成された署名を格納するには小さすぎる場合に返されます。
    \return MEMORY_E 関数実行中にメモリの割り当てエラーが発生した場合に返されます。

    \param [in] in 署名するメッセージを含むバッファへのポインタ。
    \param [in] inlen 署名するメッセージの長さ。
    \param [out] out 生成された署名を格納するバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功した後、outに書き込まれたバイト数が格納されます。
    \param [in] key 署名を生成するために使用する秘密ed25519_keyへのポインタ。

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // 生成された署名を保持
    sigSz = sizeof(sig);
    byte message[] = { メッセージで初期化 };

    wc_InitRng(&rng); // rngを初期化
    wc_ed25519_init(&key); // keyを初期化
    wc_ed25519_make_key(&rng, 32, &key); // 公開/秘密鍵ペアを作成
    ret = wc_ed25519_sign_msg(message, sizeof(message), sig, &sigSz, &key);
    if (ret != 0) {
        // メッセージ署名の生成エラー
    }
    \endcode

    \sa wc_ed25519ctx_sign_msg
    \sa wc_ed25519ph_sign_hash
    \sa wc_ed25519ph_sign_msg
    \sa wc_ed25519_verify_msg
*/

int wc_ed25519_sign_msg(const byte* in, word32 inlen, byte* out,
                        word32 *outlen, ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにed25519_keyオブジェクトを使用してメッセージに署名します。コンテキストは署名されるデータの一部です。

    \return 0 メッセージの署名の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、または出力バッファが生成された署名を格納するには小さすぎる場合に返されます。
    \return MEMORY_E 関数実行中にメモリの割り当てエラーが発生した場合に返されます。

    \param [in] in 署名するメッセージを含むバッファへのポインタ。
    \param [in] inlen 署名するメッセージの長さ。
    \param [out] out 生成された署名を格納するバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功した後、outに書き込まれたバイト数が格納されます。
    \param [in] key 署名を生成するために使用する秘密ed25519_keyへのポインタ。
    \param [in] context メッセージが署名されているコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファの長さ。

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // 生成された署名を保持
    sigSz = sizeof(sig);
    byte message[] = { メッセージで初期化 };
    byte context[] = { 署名のコンテキストで初期化 };

    wc_InitRng(&rng); // rngを初期化
    wc_ed25519_init(&key); // keyを初期化
    wc_ed25519_make_key(&rng, 32, &key); // 公開/秘密鍵ペアを作成
    ret = wc_ed25519ctx_sign_msg(message, sizeof(message), sig, &sigSz, &key,
            context, sizeof(context));
    if (ret != 0) {
        // メッセージ署名の生成エラー
    }
    \endcode

    \sa wc_ed25519_sign_msg
    \sa wc_ed25519ph_sign_hash
    \sa wc_ed25519ph_sign_msg
    \sa wc_ed25519_verify_msg
*/

int wc_ed25519ctx_sign_msg(const byte* in, word32 inlen, byte* out,
                        word32 *outlen, ed25519_key* key,
                        const byte* context, byte contextLen);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにed25519_keyオブジェクトを使用してメッセージダイジェストに署名します。コンテキストは署名されるデータの一部として含まれます。メッセージは署名計算前に事前ハッシュ化されます。

    \return 0 メッセージダイジェストの署名の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、または出力バッファが生成された署名を格納するには小さすぎる場合に返されます。
    \return MEMORY_E 関数実行中にメモリの割り当てエラーが発生した場合に返されます。

    \param [in] hash 署名するメッセージのハッシュを含むバッファへのポインタ。
    \param [in] hashLen 署名するメッセージのハッシュの長さ。
    \param [out] out 生成された署名を格納するバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功した後、outに書き込まれたバイト数が格納されます。
    \param [in] key 署名を生成するために使用する秘密ed25519_keyへのポインタ。
    \param [in] context メッセージが署名されているコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファの長さ。

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // 生成された署名を保持
    sigSz = sizeof(sig);
    byte hash[] = { メッセージのSHA-512ハッシュで初期化 };
    byte context[] = { 署名のコンテキストで初期化 };

    wc_InitRng(&rng); // rngを初期化
    wc_ed25519_init(&key); // keyを初期化
    wc_ed25519_make_key(&rng, 32, &key); // 公開/秘密鍵ペアを作成
    ret = wc_ed25519ph_sign_hash(hash, sizeof(hash), sig, &sigSz, &key,
            context, sizeof(context));
    if (ret != 0) {
        // メッセージ署名の生成エラー
    }
    \endcode

    \sa wc_ed25519_sign_msg
    \sa wc_ed25519ctx_sign_msg
    \sa wc_ed25519ph_sign_msg
    \sa wc_ed25519_verify_msg
*/

int wc_ed25519ph_sign_hash(const byte* hash, word32 hashLen, byte* out,
                           word32 *outLen, ed25519_key* key,
                           const byte* context, byte contextLen);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにed25519_keyオブジェクトを使用してメッセージに署名します。コンテキストは署名されるデータの一部として含まれます。メッセージは署名計算前に事前ハッシュ化されます。

    \return 0 メッセージの署名の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、または出力バッファが生成された署名を格納するには小さすぎる場合に返されます。
    \return MEMORY_E 関数実行中にメモリの割り当てエラーが発生した場合に返されます。

    \param [in] in 署名するメッセージを含むバッファへのポインタ。
    \param [in] inlen 署名するメッセージの長さ。
    \param [out] out 生成された署名を格納するバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功した後、outに書き込まれたバイト数が格納されます。
    \param [in] key 署名を生成するために使用する秘密ed25519_keyへのポインタ。
    \param [in] context メッセージが署名されているコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファの長さ。

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // 生成された署名を保持
    sigSz = sizeof(sig);
    byte message[] = { メッセージで初期化 };
    byte context[] = { 署名のコンテキストで初期化 };

    wc_InitRng(&rng); // rngを初期化
    wc_ed25519_init(&key); // keyを初期化
    wc_ed25519_make_key(&rng, 32, &key); // 公開/秘密鍵ペアを作成
    ret = wc_ed25519ph_sign_msg(message, sizeof(message), sig, &sigSz, &key,
            context, sizeof(context));
    if (ret != 0) {
        // メッセージ署名の生成エラー
    }
    \endcode

    \sa wc_ed25519_sign_msg
    \sa wc_ed25519ctx_sign_msg
    \sa wc_ed25519ph_sign_hash
    \sa wc_ed25519_verify_msg
*/

int wc_ed25519ph_sign_msg(const byte* in, word32 inlen, byte* out,
                        word32 *outlen, ed25519_key* key,
                        const byte* context, byte contextLen);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにメッセージのEd25519署名を検証します。答えはretを通じて返され、1は有効な署名に対応し、0は無効な署名に対応します。

    \return 0 署名の検証と認証の実行に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、またはsiglenが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E 検証は完了したが、生成された署名が提供された署名と一致しない場合に返されます。

    \param [in] sig 検証する署名を含むバッファへのポインタ。
    \param [in] siglen 検証する署名の長さ。
    \param [in] msg 検証するメッセージを含むバッファへのポインタ。
    \param [in] msgLen 検証するメッセージの長さ。
    \param [out] ret 検証結果へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するために使用する公開Ed25519鍵へのポインタ。

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { 受信した署名で初期化 };
    byte msg[] = { メッセージで初期化 };
    // 受信した公開鍵でkeyを初期化
    ret = wc_ed25519_verify_msg(sig, sizeof(sig), msg, sizeof(msg), &verified,
            &key);
    if (ret < 0) {
        // 検証実行エラー
    } else if (verified == 0)
        // 署名が無効
    }
    \endcode

    \sa wc_ed25519ctx_verify_msg
    \sa wc_ed25519ph_verify_hash
    \sa wc_ed25519ph_verify_msg
    \sa wc_ed25519_sign_msg
*/

int wc_ed25519_verify_msg(const byte* sig, word32 siglen, const byte* msg,
                          word32 msgLen, int* ret, ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにメッセージのEd25519署名を検証します。コンテキストは検証されるデータの一部として含まれます。答えはretを通じて返され、1は有効な署名に対応し、0は無効な署名に対応します。

    \return 0 署名の検証と認証の実行に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、またはsiglenが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E 検証は完了したが、生成された署名が提供された署名と一致しない場合に返されます。

    \param [in] sig 検証する署名を含むバッファへのポインタ。
    \param [in] siglen 検証する署名の長さ。
    \param [in] msg 検証するメッセージを含むバッファへのポインタ。
    \param [in] msgLen 検証するメッセージの長さ。
    \param [out] ret 検証結果へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するために使用する公開Ed25519鍵へのポインタ。
    \param [in] context メッセージが署名されたコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファの長さ。

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { 受信した署名で初期化 };
    byte msg[] = { メッセージで初期化 };
    byte context[] = { 署名のコンテキストで初期化 };
    // 受信した公開鍵でkeyを初期化
    ret = wc_ed25519ctx_verify_msg(sig, sizeof(sig), msg, sizeof(msg),
            &verified, &key, );
    if (ret < 0) {
        // 検証実行エラー
    } else if (verified == 0)
        // 署名が無効
    }
    \endcode

    \sa wc_ed25519_verify_msg
    \sa wc_ed25519ph_verify_hash
    \sa wc_ed25519ph_verify_msg
    \sa wc_ed25519_sign_msg
*/

int wc_ed25519ctx_verify_msg(const byte* sig, word32 siglen, const byte* msg,
                             word32 msgLen, int* ret, ed25519_key* key,
                             const byte* context, byte contextLen);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにメッセージのダイジェストのEd25519署名を検証します。コンテキストは検証されるデータの一部として含まれます。ハッシュは署名計算前の事前ハッシュ化されたメッセージです。メッセージダイジェストの作成に使用されるハッシュアルゴリズムはSHA-512である必要があります。答えはretを通じて返され、1は有効な署名に対応し、0は無効な署名に対応します。


    \return 0 署名の検証と認証の実行に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、またはsiglenが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E 検証は完了したが、生成された署名が提供された署名と一致しない場合に返されます。

    \param [in] sig 検証する署名を含むバッファへのポインタ。
    \param [in] siglen 検証する署名の長さ。
    \param [in] hash 検証するメッセージのハッシュを含むバッファへのポインタ。
    \param [in] hashLen 検証するハッシュの長さ。
    \param [out] ret 検証結果へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するために使用する公開Ed25519鍵へのポインタ。
    \param [in] context メッセージが署名されたコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファの長さ。

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { 受信した署名で初期化 };
    byte hash[] = { メッセージのSHA-512ハッシュで初期化 };
    byte context[] = { 署名のコンテキストで初期化 };
    // 受信した公開鍵でkeyを初期化
    ret = wc_ed25519ph_verify_hash(sig, sizeof(sig), msg, sizeof(msg),
            &verified, &key, );
    if (ret < 0) {
        // 検証実行エラー
    } else if (verified == 0)
        // 署名が無効
    }
    \endcode

    \sa wc_ed25519_verify_msg
    \sa wc_ed25519ctx_verify_msg
    \sa wc_ed25519ph_verify_msg
    \sa wc_ed25519_sign_msg
*/

int wc_ed25519ph_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                             word32 hashLen, int* ret, ed25519_key* key,
                             const byte* context, byte contextLen);

/*!
    \ingroup ED25519

    \brief この関数は、真正性を保証するためにメッセージのEd25519署名を検証します。コンテキストは検証されるデータの一部として含まれます。メッセージは検証前に事前ハッシュ化されます。答えはretを通じて返され、1は有効な署名に対応し、0は無効な署名に対応します。

    \return 0 署名の検証と認証の実行に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価された場合、またはsiglenが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E 検証は完了したが、生成された署名が提供された署名と一致しない場合に返されます。

    \param [in] sig 検証する署名を含むバッファへのポインタ。
    \param [in] siglen 検証する署名の長さ。
    \param [in] msg 検証するメッセージを含むバッファへのポインタ。
    \param [in] msgLen 検証するメッセージの長さ。
    \param [out] ret 検証結果へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するために使用する公開Ed25519鍵へのポインタ。
    \param [in] context メッセージが署名されたコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファの長さ。

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { 受信した署名で初期化 };
    byte msg[] = { メッセージで初期化 };
    byte context[] = { 署名のコンテキストで初期化 };
    // 受信した公開鍵でkeyを初期化
    ret = wc_ed25519ctx_verify_msg(sig, sizeof(sig), msg, sizeof(msg),
            &verified, &key, );
    if (ret < 0) {
        // 検証実行エラー
    } else if (verified == 0)
        // 署名が無効
    }
    \endcode

    \sa wc_ed25519_verify_msg
    \sa wc_ed25519ph_verify_hash
    \sa wc_ed25519ph_verify_msg
    \sa wc_ed25519_sign_msg
*/

int wc_ed25519ph_verify_msg(const byte* sig, word32 siglen, const byte* msg,
                            word32 msgLen, int* ret, ed25519_key* key,
                            const byte* context, byte contextLen);

/*!
    \ingroup ED25519

    \brief この関数は、メッセージ検証での将来の使用のためにed25519_keyオブジェクトを初期化します。

    \return 0 ed25519_keyオブジェクトの初期化に成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key 初期化するed25519_keyオブジェクトへのポインタ。

    _Example_
    \code
    ed25519_key key;
    wc_ed25519_init(&key);
    \endcode

    \sa wc_ed25519_make_key
    \sa wc_ed25519_free
*/

int wc_ed25519_init(ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、使用後にEd25519オブジェクトを解放します。

    \param [in,out] key 解放するed25519_keyオブジェクトへのポインタ

    _Example_
    \code
    ed25519_key key;
    // keyを初期化し、安全な交換を実行
    ...
    wc_ed25519_free(&key);
    \endcode

    \sa wc_ed25519_init
*/

void wc_ed25519_free(ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、公開鍵を含むバッファから公開ed25519_keyをインポートします。この関数は、圧縮キーと非圧縮キーの両方を処理します。公開鍵は、秘密鍵が存在する場合にそれと一致するかチェックされます。

    \return 0 ed25519_keyのインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG inまたはkeyがNULLと評価された場合、またはinLenがEd25519鍵のサイズより小さい場合に返されます。

    \param [in] in 公開鍵を含むバッファへのポインタ。
    \param [in] inLen 公開鍵を含むバッファの長さ。
    \param [in,out] key 公開鍵を格納するed25519_keyオブジェクトへのポインタ。

    _Example_
    \code
    int ret;
    byte pub[] = { Ed25519公開鍵で初期化 };

    ed_25519 key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_public(pub, sizeof(pub), &key);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_ed25519_import_public_ex
    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_import_private_key_ex
    \sa wc_ed25519_export_public
*/

int wc_ed25519_import_public(const byte* in, word32 inLen, ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、公開鍵を含むバッファから公開ed25519_keyをインポートします。この関数は、圧縮キーと非圧縮キーの両方を処理します。信頼されていない場合、秘密鍵が存在するときに公開鍵が秘密鍵と一致するかチェックします。

    \return 0 ed25519_keyのインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG inまたはkeyがNULLと評価された場合、またはinLenがEd25519鍵のサイズより小さい場合に返されます。

    \param [in] in 公開鍵を含むバッファへのポインタ。
    \param [in] inLen 公開鍵を含むバッファの長さ。
    \param [in,out] key 公開鍵を格納するed25519_keyオブジェクトへのポインタ。
    \param [in] trusted 公開鍵データが信頼されているかどうか。

    _Example_
    \code
    int ret;
    byte pub[] = { Ed25519公開鍵で初期化 };

    ed_25519 key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_public_ex(pub, sizeof(pub), &key, 1);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_ed25519_import_public
    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_import_private_key_ex
    \sa wc_ed25519_export_public
*/

int wc_ed25519_import_public_ex(const byte* in, word32 inLen, ed25519_key* key,
    int trusted);

/*!
    \ingroup ED25519

    \brief この関数は、バッファからEd25519秘密鍵のみをインポートします。

    \return 0 Ed25519鍵のインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG privまたはkeyがNULLと評価された場合、またはprivSzがED25519_KEY_SIZEと等しくない場合に返されます。

    \param [in] priv 秘密鍵を含むバッファへのポインタ。
    \param [in] privSz 秘密鍵の長さ。
    \param [in,out] key インポートされた秘密鍵を格納するed25519_keyオブジェクトへのポインタ。

    _Example_
    \code
    int ret;
    byte priv[] = { 32バイトの秘密鍵で初期化 };

    ed25519_key key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_private_only(priv, sizeof(priv), &key);
    if (ret != 0) {
        // 秘密鍵のインポートエラー
    }
    \endcode

    \sa wc_ed25519_import_public
    \sa wc_ed25519_import_public_ex
    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_import_private_key_ex
    \sa wc_ed25519_export_private_only
*/

int wc_ed25519_import_private_only(const byte* priv, word32 privSz,
                                   ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、一対のバッファから公開/秘密Ed25519鍵ペアをインポートします。この関数は、圧縮キーと非圧縮キーの両方を処理します。公開鍵は信頼されていないと想定され、秘密鍵に対してチェックされます。

    \return 0 ed25519_keyのインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG privまたはkeyがNULLと評価された場合、またはprivSzがED25519_KEY_SIZEにもED25519_PRV_KEY_SIZEにも等しくない、もしくはpubSzがED25519_PUB_KEY_SIZEより小さい場合に返されます。

    \param [in] priv 秘密鍵を含むバッファへのポインタ。
    \param [in] privSz 秘密鍵の長さ。
    \param [in] pub 公開鍵を含むバッファへのポインタ。
    \param [in] pubSz 公開鍵の長さ。
    \param [in,out] key インポートされた秘密/公開鍵ペアを格納するed25519_keyオブジェクトへのポインタ。

    _Example_
    \code
    int ret;
    byte priv[] = { 32バイトの秘密鍵で初期化 };
    byte pub[]  = { 対応する公開鍵で初期化 };

    ed25519_key key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_private_key(priv, sizeof(priv), pub, sizeof(pub),
            &key);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_ed25519_import_public
    \sa wc_ed25519_import_public_ex
    \sa wc_ed25519_import_private_only
    \sa wc_ed25519_import_private_key_ex
    \sa wc_ed25519_export_private
*/

int wc_ed25519_import_private_key(const byte* priv, word32 privSz,
                               const byte* pub, word32 pubSz, ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、一対のバッファから公開/秘密Ed25519鍵ペアをインポートします。この関数は、圧縮キーと非圧縮キーの両方を処理します。信頼されていない場合、公開鍵が秘密鍵に対してチェックされます。

    \return 0 ed25519_keyのインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG privまたはkeyがNULLと評価された場合、またはprivSzがED25519_KEY_SIZEにもED25519_PRV_KEY_SIZEにも等しくない、もしくはpubSzがED25519_PUB_KEY_SIZEより小さい場合に返されます。

    \param [in] priv 秘密鍵を含むバッファへのポインタ。
    \param [in] privSz 秘密鍵の長さ。
    \param [in] pub 公開鍵を含むバッファへのポインタ。
    \param [in] pubSz 公開鍵の長さ。
    \param [in,out] key インポートされた秘密/公開鍵ペアを格納するed25519_keyオブジェクトへのポインタ。
    \param [in] trusted 公開鍵データが信頼されているかどうか。

    _Example_
    \code
    int ret;
    byte priv[] = { 32バイトの秘密鍵で初期化 };
    byte pub[]  = { 対応する公開鍵で初期化 };

    ed25519_key key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_private_key(priv, sizeof(priv), pub, sizeof(pub),
            &key, 1);
    if (ret != 0) {
        // 鍵のインポートエラー
    }
    \endcode

    \sa wc_ed25519_import_public
    \sa wc_ed25519_import_public_ex
    \sa wc_ed25519_import_private_only
    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_export_private
*/

int wc_ed25519_import_private_key_ex(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, ed25519_key* key, int trusted);

/*!
    \ingroup ED25519

    \brief この関数は、ed25519_key構造体から公開鍵をエクスポートします。公開鍵をバッファoutに格納し、このバッファに書き込まれたバイト数をoutLenに設定します。

    \return 0 公開鍵のエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力値のいずれかがNULLと評価された場合に返されます。
    \return BUFFER_E 提供されたバッファが秘密鍵を格納するのに十分な大きさでない場合に返されます。このエラーを返す際、関数はoutLenに必要なサイズを設定します。

    \param [in] key 公開鍵をエクスポートするed25519_key構造体へのポインタ。
    \param [out] out 公開鍵を格納するバッファへのポインタ。
    \param [in,out] outLen outで利用可能なサイズを持つword32オブジェクトへのポインタ。公開鍵のエクスポートに成功した後、outに書き込まれたバイト数が設定されます。

    _Example_
    \code
    int ret;
    ed25519_key key;
    // keyを初期化し、keyを作成

    char pub[32];
    word32 pubSz = sizeof(pub);

    ret = wc_ed25519_export_public(&key, pub, &pubSz);
    if (ret != 0) {
        // 公開鍵のエクスポートエラー
    }
    \endcode

    \sa wc_ed25519_import_public
    \sa wc_ed25519_import_public_ex
    \sa wc_ed25519_export_private_only
*/

int wc_ed25519_export_public(ed25519_key* key, byte* out, word32* outLen);

/*!
    \ingroup ED25519

    \brief この関数は、ed25519_key構造体から秘密鍵のみをエクスポートします。秘密鍵をバッファoutに格納し、このバッファに書き込まれたバイト数をoutLenに設定します。

    \return 0 秘密鍵のエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力値のいずれかがNULLと評価された場合に返されます。
    \return BUFFER_E 提供されたバッファが秘密鍵を格納するのに十分な大きさでない場合に返されます。

    \param [in] key 秘密鍵をエクスポートするed25519_key構造体へのポインタ。
    \param [out] out 秘密鍵を格納するバッファへのポインタ。
    \param [in,out] outLen outで利用可能なサイズを持つword32オブジェクトへのポインタ。秘密鍵のエクスポートに成功した後、outに書き込まれたバイト数が設定されます。

    _Example_
    \code
    int ret;
    ed25519_key key;
    // keyを初期化し、keyを作成

    char priv[32]; // 秘密鍵のみなので32バイト
    word32 privSz = sizeof(priv);
    ret = wc_ed25519_export_private_only(&key, priv, &privSz);
    if (ret != 0) {
        // 秘密鍵のエクスポートエラー
    }
    \endcode

    \sa wc_ed25519_export_public
    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_import_private_key_ex
*/

int wc_ed25519_export_private_only(ed25519_key* key, byte* out, word32* outLen);

/*!
    \ingroup ED25519

    \brief この関数は、ed25519_key構造体から鍵ペアをエクスポートします。鍵ペアをバッファoutに格納し、このバッファに書き込まれたバイト数をoutLenに設定します。

    \return 0 鍵ペアのエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力値のいずれかがNULLと評価された場合に返されます。
    \return BUFFER_E 提供されたバッファが鍵ペアを格納するのに十分な大きさでない場合に返されます。

    \param [in] key 鍵ペアをエクスポートするed25519_key構造体へのポインタ。
    \param [out] out 鍵ペアを格納するバッファへのポインタ。
    \param [in,out] outLen outで利用可能なサイズを持つword32オブジェクトへのポインタ。鍵ペアのエクスポートに成功した後、outに書き込まれたバイト数が設定されます。

    _Example_
    \code
    ed25519_key key;
    wc_ed25519_init(&key);

    WC_RNG rng;
    wc_InitRng(&rng);

    wc_ed25519_make_key(&rng, 32, &key); // 32バイトのEd25519鍵を初期化

    byte out[64]; // outは十分なバッファサイズである必要があります
    word32 outLen = sizeof(out);
    int key_size = wc_ed25519_export_private(&key, out, &outLen);
    if (key_size == BUFFER_E) {
        // 関数がoutLenをリセットしたかどうかを確認するため、outのサイズとoutLenを比較
    }
    \endcode

    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_import_private_key_ex
    \sa wc_ed25519_export_private_only
*/

int wc_ed25519_export_private(ed25519_key* key, byte* out, word32* outLen);

/*!
    \ingroup ED25519

    \brief この関数は、ed25519_key構造体から秘密鍵と公開鍵を個別にエクスポートします。秘密鍵をバッファprivに格納し、このバッファに書き込まれたバイト数をprivSzに設定します。公開鍵をバッファpubに格納し、このバッファに書き込まれたバイト数をpubSzに設定します。

    \return 0 鍵ペアのエクスポートに成功した場合に返されます。
    \return BAD_FUNC_ARG 入力値のいずれかがNULLと評価された場合に返されます。
    \return BUFFER_E 提供されたバッファが鍵ペアを格納するのに十分な大きさでない場合に返されます。

    \param [in] key 鍵ペアをエクスポートするed25519_key構造体へのポインタ。
    \param [out] priv 秘密鍵を格納するバッファへのポインタ。
    \param [in,out] privSz outで利用可能なサイズを持つword32オブジェクトへのポインタ。秘密鍵のエクスポートに成功した後、outに書き込まれたバイト数が設定されます。
    \param [out] pub 公開鍵を格納するバッファへのポインタ。
    \param [in,out] pubSz outで利用可能なサイズを持つword32オブジェクトへのポインタ。公開鍵のエクスポートに成功した後、outに書き込まれたバイト数が設定されます。

    _Example_
    \code
    int ret;
    ed25519_key key;
    // keyを初期化し、keyを作成

    char pub[32];
    word32 pubSz = sizeof(pub);
    char priv[32];
    word32 privSz = sizeof(priv);

    ret = wc_ed25519_export_key(&key, priv, &pubSz, pub, &pubSz);
    if (ret != 0) {
        // 公開鍵のエクスポートエラー
    }
    \endcode

    \sa wc_ed25519_export_private
    \sa wc_ed25519_export_public
*/

int wc_ed25519_export_key(ed25519_key* key,
                          byte* priv, word32 *privSz,
                          byte* pub, word32 *pubSz);

/*!
    \ingroup ED25519

    \brief この関数は、ed25519_key構造体内の公開鍵が秘密鍵と一致するかチェックします。

    \return 0 秘密鍵と公開鍵が一致した場合に返されます。
    \return BAD_FUNC_ARG 指定されたkeyがNULLの場合に返されます。
    \return PUBLIC_KEY_E 公開鍵が利用できない、または無効な場合に返されます。

    \param [in] key 秘密鍵と公開鍵を保持するed25519_key構造体へのポインタ。

    _Example_
    \code
    int ret;
    byte priv[] = { 57バイトの秘密鍵で初期化 };
    byte pub[]  = { 対応する公開鍵で初期化 };

    ed25519_key key;
    wc_ed25519_init_key(&key);
    wc_ed25519_import_private_key_ex(priv, sizeof(priv), pub, sizeof(pub), &key,
        1);
    ret = wc_ed25519_check_key(&key);
    if (ret != 0) {
        // 鍵のチェックエラー
    }
    \endcode

    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_import_private_key_ex
*/

int wc_ed25519_check_key(ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、Ed25519のサイズ（32バイト）を返します。

    \return ED25519_KEY_SIZE 有効な秘密鍵のサイズ（32バイト）。
    \return BAD_FUNC_ARG 指定されたkeyがNULLの場合に返されます。

    \param [in] key 鍵サイズを取得するed25519_key構造体へのポインタ。

    _Example_
    \code
    int keySz;
    ed25519_key key;
    // keyを初期化し、keyを作成
    keySz = wc_ed25519_size(&key);
    if (keySz == 0) {
        // 鍵サイズの決定エラー
    }
    \endcode

    \sa wc_ed25519_make_key
*/

int wc_ed25519_size(ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、秘密鍵のサイズ（秘密 + 公開）をバイト単位で返します。

    \return ED25519_PRV_KEY_SIZE 秘密鍵のサイズ（64バイト）。
    \return BAD_FUNC_ARG key引数がNULLの場合に返されます。

    \param [in] key 鍵サイズを取得するed25519_key構造体へのポインタ。

    _Example_
    \code
    ed25519_key key;
    wc_ed25519_init(&key);

    WC_RNG rng;
    wc_InitRng(&rng);

    wc_ed25519_make_key(&rng, 32, &key); // 32バイトのEd25519鍵を初期化
    int key_size = wc_ed25519_priv_size(&key);
    \endcode

    \sa wc_ed25519_pub_size
*/

int wc_ed25519_priv_size(ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、圧縮鍵のサイズをバイト単位で返します（公開鍵）。

    \return ED25519_PUB_KEY_SIZE 圧縮公開鍵のサイズ（32バイト）。
    \return BAD_FUNC_ARG key引数がNULLの場合に返されます。

    \param [in] key 鍵サイズを取得するed25519_key構造体へのポインタ。

    _Example_
    \code
    ed25519_key key;
    wc_ed25519_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);

    wc_ed25519_make_key(&rng, 32, &key); // 32バイトのEd25519鍵を初期化
    int key_size = wc_ed25519_pub_size(&key);
    \endcode

    \sa wc_ed25519_priv_size
*/

int wc_ed25519_pub_size(ed25519_key* key);

/*!
    \ingroup ED25519

    \brief この関数は、Ed25519署名のサイズ（バイト単位で64）を返します。

    \return ED25519_SIG_SIZE Ed25519署名のサイズ（64バイト）。
    \return BAD_FUNC_ARG key引数がNULLの場合に返されます。

    \param [in] key 署名サイズを取得するed25519_key構造体へのポインタ。

    _Example_
    \code
    int sigSz;
    ed25519_key key;
    // keyを初期化し、keyを作成

    sigSz = wc_ed25519_sig_size(&key);
    if (sigSz == 0) {
        // 署名サイズの決定エラー
    }
    \endcode

    \sa wc_ed25519_sign_msg
*/

int wc_ed25519_sig_size(ed25519_key* key);