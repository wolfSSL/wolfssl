/*!
    \ingroup ED25519
    \brief  この関数はEd25519秘密鍵からEd25519公開鍵を生成します。公開鍵をバッファpubkeyに出力します。
     この関数の呼び出しに先立ち、ed25519_key構造体にはEd25519秘密鍵がインポートされている必要があります。

    \return 0  公開鍵の作成に成功したときに返されます。
    \return BAD_FUNC_ARG 引数keyまたはpubKeyがNULLの場合、または指定された鍵サイズが32バイトではない場合（ED25519に32バイトのキーがあります）。
    \return ECC_PRIV_KEY_E ed25519_key構造体にEd25519秘密鍵がインポートされていない場合に返されます。
    \return MEMORY_E  関数の実行中にメモリを割り当てエラーがある場合に返されます。

    \param [in] key Ed25519秘密鍵がインポートされているed25519_key構造体へのポインタ。
    \param [out] pubKey 公開鍵を出力するバッファへのポインタ。
    \param [in] pubKeySz バッファのサイズ。常にED25519_PUB_KEY_SIZE(32)でなければなりません。

    _Example_
    \code
    int ret;

    ed25519_key key;
    byte priv[] = { initialize with 32 byte private key };
    byte pub[32];
    word32 pubSz = sizeof(pub);

    wc_ed25519_init(&key);
    wc_ed25519_import_private_only(priv, sizeof(priv), &key);
    ret = wc_ed25519_make_public(&key, pub, &pubSz);
    if (ret != 0) {
        // error making public key
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
    \brief  この関数は新しいed25519_key構造体を生成し、それを引数keyのバッファに格納します。
    \return 0  ed25519_key構造体を正常に生成すると返されます。
    \return BAD_FUNC_ARG  RNGまたはKEYがNULLに評価された場合、または指定されたkeysizeが32バイトではない場合(Ed25519鍵には常に32バイトを指定する必要があります)。
    \return MEMORY_E  関数の実行中にメモリ割り当てエラーが発生した場合に返されます。
    \param [in] rng RNGキーを生成する初期化されたRNGオブジェクトへのポインタ。
    \param [in] keysize keyの長さ。ED25519の場合は常に32になります。

    _Example_
    \code
    int ret;

    WC_RNG rng;
    ed25519_key key;

    wc_InitRng(&rng);
    wc_ed25519_init(&key);
    wc_ed25519_make_key(&rng, 32, &key);
    if (ret != 0) {
        // error making key
    }
    \endcode
    \sa wc_ed25519_init
*/

int wc_ed25519_make_key(WC_RNG* rng, int keysize, ed25519_key* key);

/*!
    \ingroup ED25519
    \brief  この関数は、ed25519_key構造体を使用してメッセージに署名します。
    \return 0  メッセージの署名を正常に生成すると返されます。
    \return BAD_FUNC_ARG  入力パラメータのいずれかがNULLに評価された場合、または出力バッファが小さすぎて生成された署名を保存する場合は返されます。
    \return MEMORY_E  関数の実行中にメモリ割り当てエラーが発生した場合に返されます。

    \param [in] in 署名するメッセージを含むバッファへのポインタ。
    \param [in] inlen 署名するメッセージのサイズ
    \param [out] out 生成された署名を格納するためのバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功したときに、書き込まれたバイト数を保持します。
    \param [in] key 署名を生成するために使用する秘密鍵を保持しているed25519_key構造体へのポインタ。

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // will hold generated signature
    sigSz = sizeof(sig);
    byte message[] = { initialize with message };

    wc_InitRng(&rng); // initialize rng
    wc_ed25519_init(&key); // initialize key
    wc_ed25519_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ed25519_sign_msg(message, sizeof(message), sig, &sigSz, &key);
    if (ret != 0) {
        // error generating message signature
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
    \brief  この関数は、ed25519_key構造体を使用してメッセージに署名します。
    コンテキストは署名されるデータの一部です。
    \return 0  メッセージの署名を正常に生成すると返されます。
    \return BAD_FUNC_ARG  返された入力パラメータはNULLに評価されます。出力バッファが小さすぎて生成された署名を保存するには小さすぎます。
    \return MEMORY_E  関数の実行中にメモリ割り当てエラーが発生した場合に返されます。
    \param [in] in 署名するメッセージを含むバッファへのポインタ。
    \param [in] inlen 署名するメッセージのサイズ
    \param [out] out 生成された署名を格納するためのバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功したときに、書き込まれたバイトを保存します。
    \param [in] key 署名を生成するために使用する秘密鍵を保持しているed25519_key構造体へのポインタ。
    \param [in] context メッセージが署名されているコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファのサイズ

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // will hold generated signature
    sigSz = sizeof(sig);
    byte message[] = { initialize with message };
    byte context[] = { initialize with context of signing };

    wc_InitRng(&rng); // initialize rng
    wc_ed25519_init(&key); // initialize key
    wc_ed25519_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ed25519ctx_sign_msg(message, sizeof(message), sig, &sigSz, &key,
            context, sizeof(context));
    if (ret != 0) {
        // error generating message signature
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
    \brief  この関数は、ed25519_key構造体を使用してメッセージダイジェストに署名します。
    コンテキストは署名されるデータの一部として含まれています。
    署名計算の前にメッセージは事前にハッシュされています。
    メッセージダイジェストを作成するために使用されるハッシュアルゴリズムはShake-256でなければなりません。

    \return 0  メッセージダイジェストの署名を正常に生成すると返されます。
    \return BAD_FUNC_ARG  返された入力パラメータはNULLに評価されます。出力バッファが小さすぎて生成された署名を保存するには小さすぎます。
    \return MEMORY_E  関数の実行中にメモリ割り当てエラーが発生した場合に返されます。

    \param [in] hash 署名するメッセージのハッシュを含むバッファへのポインタ。
    \param [in] hashLen 署名するメッセージのハッシュのサイズ
    \param [out] out 生成された署名を格納するためのバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功したときに、書き込まれたバイトを保存します。
    \param [in] key 署名を生成するのに使用する秘密鍵を含んだed25519_key構造体へのポインタ。
    \param [in] context メッセージが署名されているコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファのサイズ

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // will hold generated signature
    sigSz = sizeof(sig);
    byte hash[] = { initialize with SHA-512 hash of message };
    byte context[] = { initialize with context of signing };

    wc_InitRng(&rng); // initialize rng
    wc_ed25519_init(&key); // initialize key
    wc_ed25519_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ed25519ph_sign_hash(hash, sizeof(hash), sig, &sigSz, &key,
            context, sizeof(context));
    if (ret != 0) {
        // error generating message signature
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
    \brief  この関数は、ed25519_key構造体を使用して認証を保証するメッセージに署名します。コンテキストは署名されたデータの一部として含まれています。署名計算の前にメッセージは事前にハッシュされています。
    \return 0  メッセージの署名を正常に生成すると返されます。
    \return BAD_FUNC_ARG  返された入力パラメータはNULLに評価されます。出力バッファが小さすぎて生成された署名を保存するには小さすぎます。
    \return MEMORY_E  関数の実行中にメモリを割り当てエラーが発生した場合に返されます。
    \param [in] in 署名するメッセージを含むバッファへのポインタ。
    \param [in] inlen 署名するメッセージのインレル長。
    \param [out] out 生成された署名を格納するためのバッファ。
    \param [in,out] outlen 出力バッファの最大長。メッセージ署名の生成に成功したときに、書き込まれたバイトを保存します。
    \param [in] key 署名を生成するプライベートed25519_key構造体へのポインタ。
    \param [in] context メッセージが署名されているコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファのサイズ

    _Example_
    \code
    ed25519_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[64]; // will hold generated signature
    sigSz = sizeof(sig);
    byte message[] = { initialize with message };
    byte context[] = { initialize with context of signing };

    wc_InitRng(&rng); // initialize rng
    wc_ed25519_init(&key); // initialize key
    wc_ed25519_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ed25519ph_sign_msg(message, sizeof(message), sig, &sigSz, &key,
            context, sizeof(context));
    if (ret != 0) {
        // error generating message signature
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
    \brief  この関数はメッセージのEd25519署名を検証します。
    retを介して答えを返し、有効な署名の場合は1、無効な署名の場合には0を返します。

    \return 0  署名検証と認証を正常に実行したときに返されます。
    \return BAD_FUNC_ARG  いずれかの入力パラメータがNULLに評価された場合、またはSIGLENが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E  検証が完了した場合は返されますが、生成された署名は提供された署名と一致しません。

    \param [in] sig 検証するシグネチャを含むバッファへのポインタ。
    \param [in] siglen 検証するシグネチャのサイズ
    \param [in] msg メッセージを含むバッファへのポインタ
    \param [in] msgLen 検証するメッセージのサイズ
    \param [out] ret 検証の結果を格納する変数へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するためのEd25519公開鍵へのポインタ。

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { initialize with received signature };
    byte msg[] = { initialize with message };
    // initialize key with received public key
    ret = wc_ed25519_verify_msg(sig, sizeof(sig), msg, sizeof(msg), &verified,
            &key);
    if (ret < 0) {
        // error performing verification
    } else if (verified == 0)
        // the signature is invalid
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
    \brief  この関数はメッセージのEd25519署名を検証します。
    コンテキストは署名されたデータの一部として含まれています。
    答えは変数retを介して返され、署名が有効ならば1、無効ならば0を返します。

    \return 0  署名検証と認証を正常に実行したときに返されます。
    \return BAD_FUNC_ARG  いずれかの入力パラメータがNULLに評価された場合、またはSIGLENが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E  検証が完了した場合は返されますが、生成された署名は提供された署名と一致しません。

    \param [in] sig 検証するシグネチャを含むバッファへのポインタ。
    \param [in] siglen 検証するシグネチャのサイズ
    \param [in] msg メッセージを含むバッファへのポインタ
    \param [in] msgLen 検証するメッセージのサイズ
    \param [out] ret 検証の結果を格納する変数へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するためのEd25519公開鍵へのポインタ。
    \param [in] context メッセージが署名されているコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストバッファのサイズ

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { initialize with received signature };
    byte msg[] = { initialize with message };
    byte context[] = { initialize with context of signature };
    // initialize key with received public key
    ret = wc_ed25519ctx_verify_msg(sig, sizeof(sig), msg, sizeof(msg),
            &verified, &key, );
    if (ret < 0) {
        // error performing verification
    } else if (verified == 0)
        // the signature is invalid
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
    \brief  この関数は、メッセージのダイジェストのEd25519署名を検証します。
    引数hashは、署名計算前のプリハッシュメッセージです。
    メッセージダイジェストを作成するために使用されるハッシュアルゴリズムはSHA-512でなければなりません。
    答えは変数retを介して返され、署名が有効ならば1、無効ならば0を返します。

    \return 0  署名検証と認証を正常に実行したときに返されます。
    \return BAD_FUNC_ARG  いずれかの入力パラメータがNULLに評価された場合、またはSIGLENが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E  検証が完了した場合は返されますが、生成された署名は提供された署名と一致しません。

    \param [in] sig 検証するシグネチャを含むバッファへのポインタ。
    \param [in] siglen 検証するシグネチャのサイズ
    \param [in] msg メッセージを含むバッファへのポインタ
    \param [in] msgLen 検証するメッセージのサイズ
    \param [out] ret 検証の結果を格納する変数へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するためのEd25519公開鍵へのポインタ。
    \param [in] context メッセージが署名されたコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストのサイズ

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { initialize with received signature };
    byte hash[] = { initialize with SHA-512 hash of message };
    byte context[] = { initialize with context of signature };
    // initialize key with received public key
    ret = wc_ed25519ph_verify_hash(sig, sizeof(sig), msg, sizeof(msg),
            &verified, &key, );
    if (ret < 0) {
        // error performing verification
    } else if (verified == 0)
        // the signature is invalid
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
    \brief  この関数は、メッセージのダイジェストのEd25519署名を検証します。
    引数contextは検証すべきデータの一部として含まれています。
    検証前にメッセージがプリハッシュされています。
    答えは変数resを介して返され、署名が有効ならば1、無効ならば0を返します。

    \return 0  署名検証と認証を正常に実行したときに返されます。
    \return BAD_FUNC_ARG  いずれかの入力パラメータがNULLに評価された場合、またはSIGLENが署名の実際の長さと一致しない場合に返されます。
    \return SIG_VERIFY_E  検証が完了した場合は返されますが、生成された署名は提供された署名と一致しません。
    \param [in] sig 検証するシグネチャを含むバッファへのポインタ。
    \param [in] siglen 検証するシグネチャのサイズ
    \param [in] msg メッセージを含むバッファへのポインタ
    \param [in] msgLen 検証するメッセージのサイズ
    \param [out] ret 検証の結果を格納する変数へのポインタ。1はメッセージが正常に検証されたことを示します。
    \param [in] key 署名を検証するためのEd25519公開鍵へのポインタ。
    \param [in] context メッセージが署名されたコンテキストを含むバッファへのポインタ。
    \param [in] contextLen コンテキストのサイズ

    _Example_
    \code
    ed25519_key key;
    int ret, verified = 0;

    byte sig[] { initialize with received signature };
    byte msg[] = { initialize with message };
    byte context[] = { initialize with context of signature };
    // initialize key with received public key
    ret = wc_ed25519ctx_verify_msg(sig, sizeof(sig), msg, sizeof(msg),
            &verified, &key, );
    if (ret < 0) {
        // error performing verification
    } else if (verified == 0)
        // the signature is invalid
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
    \brief  この関数は、後のメッセージ検証で使用のためにed25519_key構造体を初期化します。
    \return 0  ed25519_key構造体の初期化に成功したときに返されます。
    \return BAD_FUNC_ARG 引数keyがNULLの場合に返されます。
    \param [in,out] key ed25519_key構造体へのポインタ

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
    \brief  この関数は、使用済みのed25519_key構造体を解放します。
    \param [in,out] key ed25519_key構造体へのポインタ

    _Example_
    \code
    ed25519_key key;
    // initialize key and perform secure exchanges
    ...
    wc_ed25519_free(&key);
    \endcode
    \sa wc_ed25519_init
*/

void wc_ed25519_free(ed25519_key* key);

/*!
    \ingroup ED25519
    \brief  この関数はバッファからed25519公開鍵をed25519_key構造体へインポートします。
    圧縮あるいは非圧縮の両方の形式の鍵を扱います。
    \return 0  ed25519公開鍵のインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG  inまたはkeyがnullに評価された場合、またはinlenがED25519鍵のサイズよりも小さい場合に返されます。

    \param [in] in 公開鍵を含んだバッファへのポインタ
    \param [in] inLen 公開鍵を含んだバッファのサイズ
    \param [in,out] key ed25519_key構造体へのポインタ

    _Example_
    \code
    int ret;
    byte pub[] = { initialize Ed25519 public key };

    ed_25519 key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_public(pub, sizeof(pub), &key);
    if (ret != 0) {
        // error importing key
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

    \brief この関数はバッファからed25519公開鍵をed25519_key構造体へインポートします。
    圧縮あるいは非圧縮の両方の形式の鍵を扱います。
    秘密鍵が既にインポートされている場合で、trusted引数が1以外の場合は両鍵が対応しているかをチェックします。

    \return 0 ed25519公開鍵のインポートに成功した場合に返されます。
    \return BAD_FUNC_ARG Returned 引数inあるいはkeyがNULLの場合,あるいは引数inLenがEd25519鍵のサイズより小さい場合に返されます。

    \param [in] in 公開鍵を含んだバッファへのポインタ
    \param [in] inLen 公開鍵を含んだバッファのサイズ
    \param [in,out] key ed25519_key構造体へのポインタ
    \param [in] trusted 公開鍵が信頼おけるか否かを示すフラグ

    _Example_
    \code
    int ret;
    byte pub[] = { initialize Ed25519 public key };

    ed_25519 key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_public_ex(pub, sizeof(pub), &key, 1);
    if (ret != 0) {
        // error importing key
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
    \brief  この関数は、ed25519秘密鍵のみをバッファからインポートします。
    \return 0  Ed25519秘密鍵のインポートに成功した際に返されます。
    \return BAD_FUNC_ARG  privまたはkeyがNULLに評価された場合、またはprivSzがED25519_KEY_SIZEと異なる場合に返されます。
    \param [in] priv 秘密鍵を含むバッファへのポインタ。
    \param [in] privSz 秘密鍵を含むバッファのサイズ

    _Example_
    \code
    int ret;
    byte priv[] = { initialize with 32 byte private key };

    ed25519_key key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_private_key(priv, sizeof(priv), &key);
    if (ret != 0) {
        // error importing private key
    }
    \endcode
    \sa wc_ed25519_import_public
    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_export_private_only
*/
int wc_ed25519_import_private_only(const byte* priv, word32 privSz,
                                   ed25519_key* key);


/*!
    \ingroup ED25519
    \brief  この関数は、Ed25519公開鍵/秘密鍵をそれぞれ含む一対のバッファからEd25519鍵ペアをインポートします。
    この関数は圧縮と非圧縮の両方の鍵を処理します。
    \return 0  Ed25519_KEYのインポートに成功しました。
    \return BAD_FUNC_ARG  privまたはkeyがNULLに評価された場合、privSzがED25519_KEY_SIZEと異なるあるいはED25519_PRV_KEY_SIZEとも異なる場合、pubSzがED25519_PUB_KEY_SIZEよりも小さい場合に返されます。
    \param [in] priv 秘密鍵を含むバッファへのポインタ。
    \param [in] privSz 秘密鍵バッファのサイズ
    \param [in] pub 公開鍵を含むバッファへのポインタ。
    \param [in] pubSz 公開鍵バッファのサイズ

    _Example_
    \code
    int ret;
    byte priv[] = { initialize with 32 byte private key };
    byte pub[]  = { initialize with the corresponding public key };

    ed25519_key key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_private_key(priv, sizeof(priv), pub, sizeof(pub),
            &key);
    if (ret != 0) {
        // error importing key
    }
    \endcode
    \sa wc_ed25519_import_public
    \sa wc_ed25519_import_private_only
    \sa wc_ed25519_export_private
*/

int wc_ed25519_import_private_key(const byte* priv, word32 privSz,
                               const byte* pub, word32 pubSz, ed25519_key* key);

/*!
    \ingroup ED25519
    \brief この関数は一対のバッファからEd25519公開鍵/秘密鍵ペアをインポートします。この関数は圧縮キーと非圧縮キーの両方を処理します。公開鍵はtrusted引数により信頼されていないとされた場合には秘密鍵に対して検証されます。
    \return 0 ed25519_keyのインポートに成功しました。
    \return BAD_FUNC_ARG Returned if privあるいはkeyがNULLに評価された場合、privSzがED25519_KEY_SIZEともED25519_PRV_KEY_SIZEとも異なる場合、pubSzがED25519_PUB_KEY_SIZEより小さい場合に返されます。
    \param [in] priv 秘密鍵を保持するバッファへのポインタ
    \param [in] privSz 秘密鍵バッファのサイズ
    \param [in] pub 公開鍵を保持するバッファへのポインタ
    \param [in] pubSz 公開鍵バッファのサイズ
    \param [in,out] key インポートされた公開鍵/秘密鍵を保持するed25519_keyオブジェクトへのポインター
    \param [in] trusted 公開鍵が信頼できるか否かを指定するフラグ

    _Example_
    \code
    int ret;
    byte priv[] = { initialize with 32 byte private key };
    byte pub[]  = { initialize with the corresponding public key };
    ed25519_key key;
    wc_ed25519_init_key(&key);
    ret = wc_ed25519_import_private_key(priv, sizeof(priv), pub, sizeof(pub),
            &key, 1);
    if (ret != 0) {
        // error importing key
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
    \brief  この関数は、ed25519_key構造体から公開鍵をエクスポートします。公開鍵をバッファoutに格納し、outLenにこのバッファに書き込まれたバイトを設定します。
    \return 0  公開鍵のエクスポートに成功したら返されます。
    \return BAD_FUNC_ARG  いずれかの入力値がNULLに評価された場合に返されます。
    \return BUFFER_E  提供されたバッファーが公開鍵を保存するのに十分な大きさでない場合に返されます。このエラーを返すと、outlenに必要なサイズを設定します。
    \param [in] key 公開鍵をエクスポートするためのed25519_key構造体へのポインタ。
    \param [out] out 公開鍵を保存するバッファへのポインタ。
    \param [in,out] outLen 公開鍵を出力する先のバッファサイズを格納するword32型変数へのポインタ。
    入力の際はバッファサイズを格納して渡し、出力の際はエクスポートした公開鍵のサイズを格納します。

    _Example_
    \code
    int ret;
    ed25519_key key;
    // initialize key, make key

    char pub[32];
    word32 pubSz = sizeof(pub);

    ret = wc_ed25519_export_public(&key, pub, &pubSz);
    if (ret != 0) {
        // error exporting public key
    }
    \endcode
    \sa wc_ed25519_import_public
    \sa wc_ed25519_export_private_only
*/

int wc_ed25519_export_public(ed25519_key* key, byte* out, word32* outLen);

/*!
    \ingroup ED25519
    \brief  この関数は、ed25519_key構造体からの秘密鍵のみをエクスポートします。秘密鍵をバッファアウトに格納し、outlenにこのバッファに書き込まれたバイトを設定します。
    \return 0  秘密鍵のエクスポートに成功したら返されます。
    \return BAD_FUNC_ARG  いずれかの入力値がNULLに評価された場合に返されます。
    \return BUFFER_E  提供されたバッファーが秘密鍵を保存するのに十分な大きさでない場合に返されます。
    \param [in] key 秘密鍵をエクスポートするためのed25519_key構造体へのポインタ。
    \param [out] out 秘密鍵を保存するバッファへのポインタ。
    \param [in,out] outLen 秘密鍵を出力する先のバッファサイズを格納するword32型変数へのポインタ。
    入力の際はバッファサイズを格納して渡し、出力の際はエクスポートした秘密鍵のサイズを格納します。

    _Example_
    \code
    int ret;
    ed25519_key key;
    // initialize key, make key

    char priv[32]; // 32 bytes because only private key
    word32 privSz = sizeof(priv);
    ret = wc_ed25519_export_private_only(&key, priv, &privSz);
    if (ret != 0) {
        // error exporting private key
    }
    \endcode
    \sa wc_ed25519_export_public
    \sa wc_ed25519_import_private_key
*/

int wc_ed25519_export_private_only(ed25519_key* key, byte* out, word32* outLen);

/*!
    \ingroup ED25519
    \brief  この関数は、ed25519_key構造体から鍵ペアをエクスポートします。鍵ペアをバッファoutに格納し、ounterenでこのバッファに書き込まれたバイトを設定します。
    \return 0  鍵ペアのエクスポートに成功したら返されます。
    \return BAD_FUNC_ARG  いずれかの入力値がNULLに評価された場合に返されます。
    \return BUFFER_E  提供されているバッファーが鍵ペアを保存するのに十分な大きさでない場合に返されます。
    \param [in]  鍵ペアをエクスポートするためのed25519_key構造体へのポインタ。
    \param [out]  鍵ペアを保存するバッファへのポインタ。
    \param [in,out] outLen 鍵ペアを出力する先のバッファサイズを格納するword32型変数へのポインタ。
    入力の際はバッファサイズを格納して渡し、出力の際はエクスポートした鍵ペアのサイズを格納します。

    _Example_
    \code
    ed25519_key key;
    wc_ed25519_init(&key);

    WC_RNG rng;
    wc_InitRng(&rng);

    wc_ed25519_make_key(&rng, 32, &key); // initialize 32 byte Ed25519 key

    byte out[64]; // out needs to be a sufficient buffer size
    word32 outLen = sizeof(out);
    int key_size = wc_ed25519_export_private(&key, out, &outLen);
    if (key_size == BUFFER_E) {
        // Check size of out compared to outLen to see if function reset outLen
    }
    \endcode
    \sa wc_ed25519_import_private_key
    \sa wc_ed25519_export_private_only
*/

int wc_ed25519_export_private(ed25519_key* key, byte* out, word32* outLen);

/*!
    \ingroup ED25519
    \brief  この関数は、ed25519_key構造体から秘密鍵と公開鍵を別々にエクスポートします。
    秘密鍵をバッファprivに格納し、priovSzにこのバッファに書き込んだバイト数を設定します。
    公開鍵をバッファpubに格納し、pubSzにこのバッファに書き込んだバイト数を設定します。
    \return 0  鍵ペアのエクスポートに成功したら返されます。
    \return BAD_FUNC_ARG  いずれかの入力値がNULLに評価された場合に返されます。
    \return BUFFER_E  提供されているバッファが鍵ペアを保存するのに十分な大きさでない場合に返されます。
    \param [in] key 鍵ペアをエクスポートするためのed25519_key構造体へのポインタ。
    \param [out] priv 秘密鍵を出力するバッファへのポインタ。
    \param [in,out] privSz 秘密鍵を出力する先のバッファのサイズを保持するword32型変数へのポインタ。
    秘密鍵のエクスポート後には書き込まれたバイト数がセットされます。
    \param [out] pub パブリックキーを出力するバッファへのポインタ
    \param [in,out] pubSz 公開鍵を出力する先のバッファのサイズを保持するword32型変数へのポインタ。
    公開鍵のエクスポート後には書き込まれたバイト数がセットされます。

    _Example_
    \code
    int ret;
    ed25519_key key;
    // initialize key, make key

    char pub[32];
    word32 pubSz = sizeof(pub);
    char priv[32];
    word32 privSz = sizeof(priv);

    ret = wc_ed25519_export_key(&key, priv, &pubSz, pub, &pubSz);
    if (ret != 0) {
        // error exporting public key
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
    \brief  この関数は、ed25519_key構造体の公開鍵をチェックします。
    \return 0  プライベートキーと公開鍵が一致した場合に返されます。
    \return BAD_FUNC_ARG  与えられた鍵がNULLの場合に返されます。
    \return PUBLIC_KEY_E 公開鍵が参照できないか無効の場合に返されます。
    \param [in] key 公開鍵と秘密鍵の両方を保持しているed25519_key構造体へのポインタ

    _Example_
    \code
    int ret;
    byte priv[] = { initialize with 57 byte private key };
    byte pub[]  = { initialize with the corresponding public key };

    ed25519_key key;
    wc_ed25519_init_key(&key);
    wc_ed25519_import_private_key(priv, sizeof(priv), pub, sizeof(pub), &key);
    ret = wc_ed25519_check_key(&key);
    if (ret != 0) {
        // error checking key
    }
    \endcode
    \sa wc_ed25519_import_private_key
*/

int wc_ed25519_check_key(ed25519_key* key);

/*!
    \ingroup ED25519
    \brief  この関数は、Ed25519  -  32バイトのサイズを返します。
    \return ED25519_KEY_SIZE  有効な秘密鍵のサイズ（32バイト）。
    \return BAD_FUNC_ARG  与えられた引数keyがNULLの場合に返されます。
    \param [in] key ed25519_key構造体へのポインタ


    _Example_
    \code
    int keySz;
    ed25519_key key;
    // initialize key, make key
    keySz = wc_ed25519_size(&key);
    if (keySz == 0) {
        // error determining key size
    }
    \endcode
    \sa wc_ed25519_make_key
*/

int wc_ed25519_size(ed25519_key* key);

/*!
    \ingroup ED25519
    \brief  この関数は、秘密鍵サイズ（secret + public）をバイト単位で返します。
    \return ED25519_PRV_KEY_SIZE  秘密鍵のサイズ（64バイト）。
    \return BAD_FUNC_ARG  key引数がnullの場合に返されます。
    \param [in] key ed25519_key構造体へのポインタ

    _Example_
    \code
    ed25519_key key;
    wc_ed25519_init(&key);

    WC_RNG rng;
    wc_InitRng(&rng);

    wc_ed25519_make_key(&rng, 32, &key); // initialize 32 byte Ed25519 key
    int key_size = wc_ed25519_priv_size(&key);
    \endcode
    \sa wc_ed25519_pub_size
*/

int wc_ed25519_priv_size(ed25519_key* key);

/*!
    \ingroup ED25519
    \brief  この関数は圧縮鍵サイズをバイト単位で返します（公開鍵）。
    \return ED25519_PUB_KEY_SIZE  圧縮公開鍵のサイズ（32バイト）。
    \return BAD_FUNC_ARG  key引数がnullの場合は返します。
    \param [in] key ed25519_key構造体へのポインタ

    _Example_
    \code
    ed25519_key key;
    wc_ed25519_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);

    wc_ed25519_make_key(&rng, 32, &key); // initialize 32 byte Ed25519 key
    int key_size = wc_ed25519_pub_size(&key);
    \endcode
    \sa wc_ed25519_priv_size
*/

int wc_ed25519_pub_size(ed25519_key* key);

/*!
    \ingroup ED25519
    \brief  この関数は、ED25519シグネチャのサイズ（バイト数64）を返します。
    \return ED25519_SIG_SIZE  ED25519シグネチャ（64バイト）のサイズ。
    \return BAD_FUNC_ARG  key引数がnullの場合は返します。
    \param [in] key ed25519_key構造体へのポインタ

    _Example_
    \code
    int sigSz;
    ed25519_key key;
    // initialize key, make key

    sigSz = wc_ed25519_sig_size(&key);
    if (sigSz == 0) {
        // error determining sig size
    }
    \endcode
    \sa wc_ed25519_sign_msg
*/

int wc_ed25519_sig_size(ed25519_key* key);
