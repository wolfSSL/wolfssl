/*!
    \ingroup ECC

    \brief この関数は新しいecc_keyを生成し、keyに格納します。

    \return 0 成功時に返されます。
    \return ECC_BAD_ARG_E rngまたはkeyがNULLと評価された場合に返されます
    \return BAD_FUNC_ARG 指定されたキーサイズがサポートされているキーの正しい範囲内にない場合に返されます
    \return MEMORY_E eccキーの計算中にメモリ割り当てエラーがある場合に返されます
    \return MP_INIT_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MEM eccキーの計算中にエラーがある場合に返される可能性があります

    \param rng キーの生成に使用する初期化されたRNGオブジェクトへのポインタ
    \param keysize ecc_keyの希望する長さ
    \param key キーを生成するecc_keyへのポインタ

    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key); // 32バイトのeccキーを初期化
    \endcode

    \sa wc_ecc_init
    \sa wc_ecc_shared_secret
*/

int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は新しいecc_keyを生成し、keyに格納します。

    \return 0 成功時に返されます。
    \return ECC_BAD_ARG_E rngまたはkeyがNULLと評価された場合に返されます
    \return BAD_FUNC_ARG 指定されたキーサイズがサポートされているキーの正しい範囲内にない場合に返されます
    \return MEMORY_E eccキーの計算中にメモリ割り当てエラーがある場合に返されます
    \return MP_INIT_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E eccキーの計算中にエラーがある場合に返される可能性があります
    \return MP_MEM eccキーの計算中にエラーがある場合に返される可能性があります

    \param key 作成されたキーを格納するポインタ。
    \param keysize 作成されるキーのサイズ（バイト単位）、curveIdに基づいて設定
    \param rng キー作成で使用されるRng
    \param curve_id キーに使用するカーブ

    _Example_
    \code
    ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP521R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
        // エラー処理
    }

    \endcode

    \sa wc_ecc_make_key
    \sa wc_ecc_get_curve_size_from_id
*/

int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key, int curve_id);

/*!
    \ingroup ECC

    \brief wc_ecc_make_pubは、既存の秘密成分を持つecc_keyから公開成分を計算します。pubOutが提供されている場合、計算された公開鍵はそこに格納されます。そうでない場合は、提供されたecc_keyの公開成分スロットに格納されます。

    \return 0 成功時に返されます。
    \return ECC_BAD_ARG_E keyがNULLの場合に返されます
    \return BAD_FUNC_ARG 提供されたキーが有効なecc_keyでない場合に返されます。
    \return MEMORY_E 公開鍵の計算中にメモリ割り当てエラーがある場合に返されます
    \return MP_INIT_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MEM 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return ECC_OUT_OF_RANGE_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return ECC_PRIV_KEY_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return ECC_INF_E 公開鍵の計算中にエラーがある場合に返される可能性があります

    \param key 有効な秘密成分を含むecc_keyへのポインタ
    \param pubOut 計算された公開鍵を格納するecc_point構造体へのオプションのポインタ

    \sa wc_ecc_make_pub_ex
    \sa wc_ecc_make_key
*/

int wc_ecc_make_pub(ecc_key* key, ecc_point* pubOut);

/*!
    \ingroup ECC

    \brief wc_ecc_make_pub_exは、既存の秘密成分を持つecc_keyから公開成分を計算します。pubOutが提供されている場合、計算された公開鍵はそこに格納されます。そうでない場合は、提供されたecc_keyの公開成分スロットに格納されます。提供されたrngがnon-NULLの場合、計算で使用される秘密鍵値をブラインドするために使用されます。

    \return 0 成功時に返されます。
    \return ECC_BAD_ARG_E keyがNULLの場合に返されます
    \return BAD_FUNC_ARG 提供されたキーが有効なecc_keyでない場合に返されます。
    \return MEMORY_E 公開鍵の計算中にメモリ割り当てエラーがある場合に返されます
    \return MP_INIT_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MEM 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return ECC_OUT_OF_RANGE_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return ECC_PRIV_KEY_E 公開鍵の計算中にエラーがある場合に返される可能性があります
    \return ECC_INF_E 公開鍵の計算中にエラーがある場合に返される可能性があります

    \param key 有効な秘密成分を含むecc_keyへのポインタ
    \param pubOut 計算された公開鍵を格納するecc_point構造体へのオプションのポインタ
    \param rng 公開鍵の計算で使用されるRng

    \sa wc_ecc_make_pub
    \sa wc_ecc_make_key
    \sa wc_InitRng
*/

int wc_ecc_make_pub_ex(ecc_key* key, ecc_point* pubOut, WC_RNG* rng);

/*!
    \ingroup ECC

    \brief eccキーの有効性に関する健全性チェックを実行します。

    \return MP_OKAY 成功、キーは正常です。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。
    \return ECC_INF_E wc_ecc_point_is_at_infinityが1を返す場合に返されます。

    \param key チェックするキーへのポインタ。

    _Example_
    \code
    ecc_key key;
    WC_RNG rng;
    int check_result;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    check_result = wc_ecc_check_key(&key);

    if (check_result == MP_OKAY)
    {
        // キーチェック成功
    }
    else
    {
        // キーチェック失敗
    }
    \endcode

    \sa wc_ecc_point_is_at_infinity
*/

int wc_ecc_check_key(ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、使用後にecc_keyキーを解放します。


    \param key 解放するecc_key構造体へのポインタ

    _Example_
    \code
    // キーを初期化してECC操作を実行
    ...
    wc_ecc_key_free(&key);
    \endcode

    \sa wc_ecc_key_new
    \sa wc_ecc_init_ex
*/

void wc_ecc_key_free(ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、ローカル秘密鍵と受信した公開鍵を使用して新しい共有秘密鍵を生成します。この共有秘密鍵をバッファoutに格納し、outlenを更新して出力バッファに書き込まれたバイト数を保持します。

    \return 0 共有秘密鍵の生成に成功した場合に返されます
    \return BAD_FUNC_ARG いずれかの入力パラメータがNULLと評価された場合に返されます
    \return ECC_BAD_ARG_E 引数として与えられた秘密鍵private_keyのタイプがECC_PRIVATEKEYでない場合、または公開鍵と秘密鍵のタイプ（ecc->dpで指定）が同等でない場合に返されます
    \return MEMORY_E 新しいeccポイントの生成中にエラーがある場合に返されます
    \return BUFFER_E 生成された共有秘密鍵が提供されたバッファに格納するには長すぎる場合に返されます
    \return MP_INIT_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E 共有鍵の計算中にエラーがある場合に返される可能性があります
    \return MP_MEM 共有鍵の計算中にエラーがある場合に返される可能性があります

    \param private_key ローカル秘密鍵を含むecc_key構造体へのポインタ
    \param public_key 受信した公開鍵を含むecc_key構造体へのポインタ
    \param out 生成された共有秘密鍵を格納する出力バッファへのポインタ
    \param outlen 出力バッファの長さを含むword32オブジェクトへのポインタ。共有秘密鍵の生成に成功すると、出力バッファに書き込まれた長さで上書きされます

    _Example_
    \code
    ecc_key priv, pub;
    WC_RNG rng;
    byte secret[1024]; // 1024バイトの共有秘密鍵を保持可能
    word32 secretSz = sizeof(secret);
    int ret;

    wc_InitRng(&rng); // rngを初期化
    wc_ecc_init(&priv); // キーを初期化
    wc_ecc_make_key(&rng, 32, &priv); // 公開/秘密鍵ペアを作成
    // 公開鍵を受信し、pubに初期化
    ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretSz);
    // 共有秘密鍵を生成
    if ( ret != 0 ) {
    	// 共有秘密鍵の生成エラー
    }
    \endcode

    \sa wc_ecc_init
    \sa wc_ecc_make_key
*/

int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
                      word32* outlen);

/*!
    \ingroup ECC

    \brief 秘密鍵と公開ポイント間でECC共有秘密を作成します。

    \return MP_OKAY 成功を示します。
    \return BAD_FUNC_ARG いずれかの引数がnullの場合に返されるエラー。
    \return ECC_BAD_ARG_E private_key->typeがECC_PRIVATEKEYでない場合、またはprivate_key->idxの検証に失敗した場合に返されるエラー。
    \return BUFFER_E outlenが小さすぎる場合のエラー。
    \return MEMORY_E 新しいポイントを作成する際のエラー。
    \return MP_VAL 初期化失敗が発生した場合に返される可能性があります。
    \return MP_MEM 初期化失敗が発生した場合に返される可能性があります。

    \param private_key 秘密ECCキー。
    \param point 使用するポイント（公開鍵）。
    \param out 共有秘密の出力先。ANSI X9.63のEC-DHに準拠。
    \param outlen 最大サイズを入力し、共有秘密の結果サイズを出力。

    _Example_
    \code
    ecc_key key;
    ecc_point* point;
    byte shared_secret[];
    int secret_size;
    int result;

    point = wc_ecc_new_point();

    result = wc_ecc_shared_secret_ex(&key, point,
    &shared_secret, &secret_size);

    if (result != MP_OKAY)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_ecc_verify_hash_ex
*/

int wc_ecc_shared_secret_ex(ecc_key* private_key, ecc_point* point,
                             byte* out, word32 *outlen);

/*!
    \ingroup ECC

    \brief この関数は、ecc_keyオブジェクトを使用してメッセージダイジェストに署名し、真正性を保証します。

    \return 0 メッセージダイジェストの署名を正常に生成した場合に返されます
    \return BAD_FUNC_ARG いずれかの入力パラメータがNULLと評価された場合、または出力バッファが生成された署名を格納するには小さすぎる場合に返されます
    \return ECC_BAD_ARG_E 入力キーが秘密鍵でない場合、またはECC OIDが無効な場合に返されます
    \return RNG_FAILURE_E rngが満足のいくキーを正常に生成できない場合に返されます
    \return MP_INIT_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MEM メッセージ署名の計算中にエラーがある場合に返される可能性があります

    \param in 署名するメッセージハッシュを含むバッファへのポインタ
    \param inlen 署名するメッセージハッシュの長さ
    \param out 生成された署名を格納するバッファ
    \param outlen 出力バッファの最大長。メッセージ署名の生成に成功すると、outに書き込まれたバイト数を格納します
    \param key 署名を生成するために使用する秘密ECCキーへのポインタ

    _Example_
    \code
    ecc_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[512]; // 生成された署名を保持
    sigSz = sizeof(sig);
    byte digest[] = { // メッセージハッシュで初期化 };
    wc_InitRng(&rng); // rngを初期化
    wc_ecc_init(&key); // キーを初期化
    wc_ecc_make_key(&rng, 32, &key); // 公開/秘密鍵ペアを作成
    ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sigSz, &key);
    if ( ret != 0 ) {
	    // メッセージ署名の生成エラー
    }
    \endcode

    \sa wc_ecc_verify_hash
*/

int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
                     WC_RNG* rng, ecc_key* key);

/*!
    \ingroup ECC

    \brief メッセージダイジェストに署名します。

    \return MP_OKAY メッセージダイジェストの署名を正常に生成した場合に返されます
    \return ECC_BAD_ARG_E 入力キーが秘密鍵でない場合、またはECC IDXが無効な場合、またはいずれかの入力パラメータがNULLと評価された場合、または出力バッファが生成された署名を格納するには小さすぎる場合に返されます
    \return RNG_FAILURE_E rngが満足のいくキーを正常に生成できない場合に返されます
    \return MP_INIT_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MEM メッセージ署名の計算中にエラーがある場合に返される可能性があります

    \param in 署名するメッセージダイジェスト。
    \param inlen ダイジェストの長さ。
    \param rng WC_RNG構造体へのポインタ。
    \param key 秘密ECCキー。
    \param r 署名のr成分の出力先。
    \param s 署名のs成分の出力先。

    _Example_
    \code
    ecc_key key;
    WC_RNG rng;
    int ret, sigSz;
    mp_int r; // 署名のr成分の出力先。
    mp_int s; // 署名のs成分の出力先。

    byte sig[512]; // 生成された署名を保持
    sigSz = sizeof(sig);
    byte digest[] = { メッセージハッシュで初期化 };
    wc_InitRng(&rng); // rngを初期化
    wc_ecc_init(&key); // キーを初期化
    mp_init(&r); // r成分を初期化
    mp_init(&s); // s成分を初期化
    wc_ecc_make_key(&rng, 32, &key); // 公開/秘密鍵ペアを作成
    ret = wc_ecc_sign_hash_ex(digest, sizeof(digest), &rng, &key, &r, &s);

    if ( ret != MP_OKAY ) {
    	// メッセージ署名の生成エラー
    }
    \endcode

    \sa wc_ecc_verify_hash_ex
*/

int wc_ecc_sign_hash_ex(const byte* in, word32 inlen, WC_RNG* rng,
                        ecc_key* key, mp_int *r, mp_int *s);

/*!
    \ingroup ECC

    \brief この関数は、真正性を確保するためにハッシュのECC署名を検証します。statを通じて答えを返し、1は有効な署名に対応し、0は無効な署名に対応します。

    \return 0 署名検証の実行に成功した場合に返されます。注：これは署名が検証されたことを意味するものではありません。真正性情報は代わりにstatに格納されます
    \return BAD_FUNC_ARG いずれかの入力パラメータがNULLと評価された場合に返されます
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます
    \return MP_INIT_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_READ_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_CMP_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MUL_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_ADD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_TO_E メッセージ署名の計算中にエラーがある場合に返される可能性があります
    \return MP_MEM メッセージ署名の計算中にエラーがある場合に返される可能性があります

    \param sig 検証する署名を含むバッファへのポインタ
    \param siglen 検証する署名の長さ
    \param hash 検証されたメッセージのハッシュを含むバッファへのポインタ
    \param hashlen 検証されたメッセージのハッシュの長さ
    \param stat 検証結果へのポインタ。1はメッセージが正常に検証されたことを示します
    \param key 署名を検証するために使用する公開ECCキーへのポインタ

    _Example_
    \code
    ecc_key key;
    int ret, verified = 0;

    byte sig[1024] { 受信した署名で初期化 };
    byte digest[] = { メッセージハッシュで初期化 };
    // 受信した公開鍵でキーを初期化
    ret = wc_ecc_verify_hash(sig, sizeof(sig), digest,sizeof(digest),
    &verified, &key);
    if ( ret != 0 ) {
	    // 検証実行エラー
    } else if ( verified == 0 ) {
	    // 署名が無効
    }
    \endcode

    \sa wc_ecc_sign_hash
    \sa wc_ecc_verify_hash_ex
*/

int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                    word32 hashlen, int* stat, ecc_key* key);

/*!
    \ingroup ECC

    \brief ECC署名を検証します。結果はstatに書き込まれます。1は有効、0は無効です。注：有効性のテストに戻り値を使用しないでください。statのみを使用してください。

    \return MP_OKAY 成功した場合（署名が有効でない場合でも）
    \return ECC_BAD_ARG_E 引数がnullの場合、またはkey-idxが無効な場合に返されます。
    \return MEMORY_E 整数またはポイントの割り当てエラー。

    \param r 検証する署名のR成分
    \param s 検証する署名のS成分
    \param hash 署名されたハッシュ（メッセージダイジェスト）
    \param hashlen ハッシュの長さ（オクテット）
    \param stat 署名の結果、1==有効、0==無効
    \param key 対応する公開ECCキー

    _Example_
    \code
    mp_int r;
    mp_int s;
    int stat;
    byte hash[] = { いくつかのハッシュ }
    ecc_key key;

    if(wc_ecc_verify_hash_ex(&r, &s, hash, hashlen, &stat, &key) == MP_OKAY)
    {
        // statをチェック
    }
    \endcode

    \sa wc_ecc_verify_hash
*/

int wc_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                          word32 hashlen, int* stat, ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、メッセージ検証または鍵交換で将来使用するためにecc_keyオブジェクトを初期化します。

    \return 0 ecc_keyオブジェクトの初期化に成功した場合に返されます
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます

    \param key 初期化するecc_keyオブジェクトへのポインタ

    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    \endcode

    \sa wc_ecc_make_key
    \sa wc_ecc_free
*/

int wc_ecc_init(ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、メッセージ検証または鍵交換で将来使用するためにecc_keyオブジェクトを初期化します。

    \return 0 ecc_keyオブジェクトの初期化に成功した場合に返されます
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます

    \param key 初期化するecc_keyオブジェクトへのポインタ
    \param heap ヒープ識別子へのポインタ
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定

    _Example_
    \code
    ecc_key key;
    wc_ecc_init_ex(&key, heap, devId);
    \endcode

    \sa wc_ecc_make_key
    \sa wc_ecc_free
    \sa wc_ecc_init
*/

int wc_ecc_init_ex(ecc_key* key, void* heap, int devId);

/*!
    \ingroup ECC

    \brief この関数は、ユーザー定義のヒープを使用し、キー構造体用のスペースを割り当てます。

    \return 0 ecc_keyオブジェクトの初期化に成功した場合に返されます
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます


    _Example_
    \code
    wc_ecc_key_new(&heap);
    \endcode

    \sa wc_ecc_make_key
    \sa wc_ecc_key_free
    \sa wc_ecc_init
*/

ecc_key* wc_ecc_key_new(void* heap);

/*!
    \ingroup ECC

    \brief この関数は、使用後にecc_keyオブジェクトを解放します。

    \return int wolfSSLのエラーまたは成功ステータスを示す整数が返されます。

    \param key 解放するecc_keyオブジェクトへのポインタ

    _Example_
    \code
    // キーを初期化して安全な交換を実行
    ...
    wc_ecc_free(&key);
    \endcode

    \sa wc_ecc_init
*/

int wc_ecc_free(ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、固定小数点キャッシュを解放します。これは計算時間を高速化するためにeccで使用できます。この機能を使用するには、FP_ECC（固定小数点ecc）を定義する必要があります。スレッド化されたアプリケーションは、スレッドを終了する前にこの関数を呼び出す必要があります。

    \return none 返り値なし。

    \param none パラメータなし。

    _Example_
    \code
    ecc_key key;
    // キーを初期化して安全な交換を実行
    ...

    wc_ecc_fp_free();
    \endcode

    \sa wc_ecc_free
*/

void wc_ecc_fp_free(void);

/*!
    \ingroup ECC

    \brief ECC idxが有効かどうかをチェックします。

    \return 1 有効な場合に返されます。
    \return 0 有効でない場合に返されます。

    \param n チェックするidx番号。

    _Example_
    \code
    ecc_key key;
    WC_RNG rng;
    int is_valid;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    is_valid = wc_ecc_is_valid_idx(key.idx);
    if (is_valid == 1)
    {
        // idxは有効
    }
    else if (is_valid == 0)
    {
        // idxは無効
    }
    \endcode

    \sa なし
*/

int wc_ecc_is_valid_idx(int n);
/*!
    \ingroup ECC

    \brief 新しいECCポイントを割り当てます。

    \return p 新しく割り当てられたポイント。
    \return NULL エラー時にNULLを返します。

    \param none パラメータなし。

    _Example_
    \code
    ecc_point* point;
    point = wc_ecc_new_point();
    if (point == NULL)
    {
        // ポイント作成エラーを処理
    }
    // ポイントで何かを行う
    \endcode

    \sa wc_ecc_del_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_copy_point
*/

ecc_point* wc_ecc_new_point(void);

/*!
    \ingroup ECC

    \brief メモリからECCポイントを解放します。

    \return none 返り値なし。

    \param p 解放するポイント。

    _Example_
    \code
    ecc_point* point;
    point = wc_ecc_new_point();
    if (point == NULL)
    {
        // ポイント作成エラーを処理
    }
    // ポイントで何かを行う
    wc_ecc_del_point(point);
    \endcode

    \sa wc_ecc_new_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_copy_point
*/

void wc_ecc_del_point(ecc_point* p);

/*!
    \ingroup ECC

    \brief あるポイントの値を別のポイントにコピーします。

    \return ECC_BAD_ARG_E pまたはrがnullの場合にスローされるエラー。
    \return MP_OKAY ポイントが正常にコピーされました
    \return ret 内部関数からのエラー。次のような可能性があります...

    \param p コピーするポイント。
    \param r 作成されたポイント。

    _Example_
    \code
    ecc_point* point;
    ecc_point* copied_point;
    int copy_return;

    point = wc_ecc_new_point();
    copy_return = wc_ecc_copy_point(point, copied_point);
    if (copy_return != MP_OKAY)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_ecc_new_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_del_point
*/

int wc_ecc_copy_point(const ecc_point* p, ecc_point *r);

/*!
    \ingroup ECC

    \brief ポイントの値を別のポイントと比較します。

    \return BAD_FUNC_ARG 一方または両方の引数がNULL。
    \return MP_EQ ポイントが等しい。
    \return ret MP_LTまたはMP_GTのいずれかで、ポイントが等しくないことを示します。

    \param a 比較する最初のポイント。
    \param b 比較する2番目のポイント。

    _Example_
    \code
    ecc_point* point;
    ecc_point* point_to_compare;
    int cmp_result;

    point = wc_ecc_new_point();
    point_to_compare = wc_ecc_new_point();
    cmp_result = wc_ecc_cmp_point(point, point_to_compare);
    if (cmp_result == BAD_FUNC_ARG)
    {
        // 引数が無効
    }
    else if (cmp_result == MP_EQ)
    {
        // ポイントが等しい
    }
    else
    {
        // ポイントが等しくない
    }
    \endcode

    \sa wc_ecc_new_point
    \sa wc_ecc_del_point
    \sa wc_ecc_copy_point
*/

int wc_ecc_cmp_point(ecc_point* a, ecc_point *b);

/*!
    \ingroup ECC

    \brief ポイントが無限遠点にあるかどうかをチェックします。ポイントが無限遠点にある場合は1を返し、そうでない場合は0を返し、エラーの場合は<0を返します

    \return 1 pが無限遠点にある。
    \return 0 pが無限遠点にない。
    \return <0 エラー。

    \param p チェックするポイント。

    _Example_
    \code
    ecc_point* point;
    int is_infinity;
    point = wc_ecc_new_point();

    is_infinity = wc_ecc_point_is_at_infinity(point);
    if (is_infinity < 0)
    {
        // エラーを処理
    }
    else if (is_infinity == 0)
    {
        // ポイントは無限遠点にない
    }
    else if (is_infinity == 1)
    {
        // ポイントは無限遠点にある
    }
    \endcode

    \sa wc_ecc_new_point
    \sa wc_ecc_del_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_copy_point
*/

int wc_ecc_point_is_at_infinity(ecc_point *p);

/*!
    \ingroup ECC

    \brief ECC固定点乗算を実行します。

    \return MP_OKAY 操作が成功した場合に返されます。
    \return MP_INIT_E 多精度整数（mp_int）ライブラリで使用するために整数を初期化する際にエラーがある場合に返されます。

    \param k 被乗数。
    \param G 乗算する基点。
    \param R 積の出力先。
    \param modulus カーブのモジュラス。
    \param map ゼロでない場合、ポイントをアフィン座標に戻してマップします。そうでない場合は、ヤコビ・モンゴメリー形式のままです。

    _Example_
    \code
    ecc_point* base;
    ecc_point* destination;
    // ポイントを初期化
    base = wc_ecc_new_point();
    destination = wc_ecc_new_point();
    // 他の引数を設定
    mp_int multiplicand;
    mp_int modulus;
    int map;
    \endcode

    \sa なし
*/

int wc_ecc_mulmod(const mp_int* k, ecc_point *G, ecc_point *R,
                  mp_int* a, mp_int* modulus, int map);

/*!
    \ingroup ECC

    \brief この関数は、ecc_key構造体からECCキーをエクスポートし、結果をoutに格納します。キーはANSI X9.63形式で格納されます。出力バッファに書き込まれたバイト数をoutLenに格納します。

    \return 0 ecc_keyのエクスポートに成功した場合に返されます
    \return LENGTH_ONLY_E 出力バッファがNULLと評価されるが、他の2つの入力パラメータが有効な場合に返されます。関数がキーを格納するために必要な長さのみを返していることを示します
    \return ECC_BAD_ARG_E いずれかの入力パラメータがNULLの場合、またはキーがサポートされていない（無効なインデックスを持つ）場合に返されます
    \return BUFFER_E 出力バッファがeccキーを格納するには小さすぎる場合に返されます。出力バッファが小さすぎる場合、必要なサイズがoutLenで返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return MP_INIT_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_READ_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_CMP_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MUL_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_ADD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_TO_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MEM ecc_keyの処理中にエラーがある場合に返される可能性があります

    \param key エクスポートするecc_keyオブジェクトへのポインタ
    \param out ANSI X9.63形式のキーを格納するバッファへのポインタ
    \param outLen 出力バッファのサイズ。キーの格納に成功すると、出力バッファに書き込まれたバイト数を保持します

    _Example_
    \code
    int ret;
    byte buff[1024];
    word32 buffSz = sizeof(buff);

    ecc_key key;
    // キーを初期化し、キーを作成
    ret = wc_ecc_export_x963(&key, buff, &buffSz);
    if ( ret != 0) {
    	// キーのエクスポートエラー
    }
    \endcode

    \sa wc_ecc_export_x963_ex
    \sa wc_ecc_import_x963
    \sa wc_ecc_make_pub
*/

int wc_ecc_export_x963(ecc_key* key, byte* out, word32* outLen);

/*!
    \ingroup ECC

    \brief この関数は、ecc_key構造体から公開鍵をエクスポートし、結果をoutに格納します。キーはANSI X9.63形式で格納されます。出力バッファに書き込まれたバイト数をoutLenに格納します。この関数は、compressedパラメータを通じて証明書を圧縮する追加オプションを提供します。このパラメータがtrueの場合、キーはANSI X9.63圧縮形式で格納されます。

    \return 0 ecc_key公開成分のエクスポートに成功した場合に返されます
    \return ECC_PRIVATEKEY_ONLY ecc_key公開成分が欠落している場合に返されます
    \return NOT_COMPILED_IN コンパイル時にHAVE_COMP_KEYが有効になっていないが、キーが圧縮形式で要求された場合に返されます
    \return LENGTH_ONLY_E 出力バッファがNULLと評価されるが、他の2つの入力パラメータが有効な場合に返されます。関数が公開鍵を格納するために必要な長さのみを返していることを示します
    \return ECC_BAD_ARG_E いずれかの入力パラメータがNULLの場合、またはキーがサポートされていない（無効なインデックスを持つ）場合に返されます
    \return BUFFER_E 出力バッファが公開鍵を格納するには小さすぎる場合に返されます。出力バッファが小さすぎる場合、必要なサイズがoutLenで返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return MP_INIT_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_READ_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_CMP_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MUL_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_ADD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_TO_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MEM ecc_keyの処理中にエラーがある場合に返される可能性があります

    \param key エクスポートするecc_keyオブジェクトへのポインタ
    \param out ANSI X9.63形式の公開鍵を格納するバッファへのポインタ
    \param outLen 出力バッファのサイズ。公開鍵の格納に成功すると、出力バッファに書き込まれたバイト数を保持します
    \param compressed キーを圧縮形式で格納するかどうかの指標。1==圧縮、0==非圧縮

    _Example_
    \code
    int ret;
    byte buff[1024];
    word32 buffSz = sizeof(buff);
    ecc_key key;
    // キーを初期化し、キーを作成
    ret = wc_ecc_export_x963_ex(&key, buff, &buffSz, 1);
    if ( ret != 0) {
	    // キーのエクスポートエラー
    }
    \endcode

    \sa wc_ecc_export_x963
    \sa wc_ecc_import_x963
    \sa wc_ecc_make_pub
*/

int wc_ecc_export_x963_ex(ecc_key* key, byte* out, word32* outLen, int compressed);

/*!
    \ingroup ECC

    \brief この関数は、ANSI X9.63形式で格納されたキーを含むバッファから公開ECCキーをインポートします。この関数は、コンパイル時にHAVE_COMP_KEYオプションを通じて圧縮キーが有効になっている限り、圧縮キーと非圧縮キーの両方を処理します。

    \return 0 ecc_keyのインポートに成功した場合に返されます
    \return NOT_COMPILED_IN コンパイル時にHAVE_COMP_KEYが有効になっていないが、キーが圧縮形式で格納されている場合に返されます
    \return ECC_BAD_ARG_E inまたはkeyがNULLと評価される場合、またはinLenが偶数の場合に返されます（x9.63標準によると、キーは奇数でなければなりません）
    \return MEMORY_E メモリの割り当てエラーがある場合に返されます
    \return ASN_PARSE_E ECCキーの解析エラーがある場合に返されます。ECCキーが有効なANSI X9.63形式で格納されていないことを示す可能性があります
    \return IS_POINT_E エクスポートされた公開鍵がECC曲線上のポイントでない場合に返されます
    \return MP_INIT_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_READ_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_CMP_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MUL_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_ADD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_TO_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MEM ecc_keyの処理中にエラーがある場合に返される可能性があります

    \param in ANSI x9.63形式のECCキーを含むバッファへのポインタ
    \param inLen 入力バッファの長さ
    \param key インポートされたキーを格納するecc_keyオブジェクトへのポインタ

    _Example_
    \code
    int ret;
    byte buff[] = { ANSI X9.63形式のキーで初期化 };

    ecc_key pubKey;
    wc_ecc_init(&pubKey);

    ret = wc_ecc_import_x963(buff, sizeof(buff), &pubKey);
    if ( ret != 0) {
    	// キーのインポートエラー
    }
    \endcode

    \sa wc_ecc_export_x963
    \sa wc_ecc_import_private_key
*/

int wc_ecc_import_x963(const byte* in, word32 inLen, ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、生の秘密鍵を含むバッファとANSI X9.63形式の公開鍵を含む2番目のバッファから公開/秘密ECCキーペアをインポートします。この関数は、コンパイル時にHAVE_COMP_KEYオプションを通じて圧縮キーが有効になっている限り、圧縮キーと非圧縮キーの両方を処理します。

    \return 0 ecc_keyのインポートに成功した場合に返されます
    NOT_COMPILED_IN コンパイル時にHAVE_COMP_KEYが有効になっていないが、キーが圧縮形式で格納されている場合に返されます
    \return ECC_BAD_ARG_E inまたはkeyがNULLと評価される場合、またはinLenが偶数の場合に返されます（x9.63標準によると、キーは奇数でなければなりません）
    \return MEMORY_E メモリの割り当てエラーがある場合に返されます
    \return ASN_PARSE_E ECCキーの解析エラーがある場合に返されます。ECCキーが有効なANSI X9.63形式で格納されていないことを示す可能性があります
    \return IS_POINT_E エクスポートされた公開鍵がECC曲線上のポイントでない場合に返されます
    \return MP_INIT_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_READ_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_CMP_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MUL_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_ADD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_TO_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MEM ecc_keyの処理中にエラーがある場合に返される可能性があります

    \param priv 生の秘密鍵を含むバッファへのポインタ
    \param privSz 秘密鍵バッファのサイズ
    \param pub ANSI x9.63形式のECC公開鍵を含むバッファへのポインタ
    \param pubSz 公開鍵入力バッファの長さ
    \param key インポートされた秘密/公開鍵ペアを格納するecc_keyオブジェクトへのポインタ

    _Example_
    \code
    int ret;
    byte pub[] = { ANSI X9.63形式のキーで初期化 };
    byte priv[] = { 生の秘密鍵で初期化 };

    ecc_key key;
    wc_ecc_init(&key);
    ret = wc_ecc_import_private_key(priv, sizeof(priv), pub, sizeof(pub),
    &key);
    if ( ret != 0) {
    	// キーのインポートエラー
    }
    \endcode

    \sa wc_ecc_export_x963
    \sa wc_ecc_import_private_key
*/

int wc_ecc_import_private_key(const byte* priv, word32 privSz, const byte* pub,
                           word32 pubSz, ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、ECC署名のRとS部分をDERエンコードされたECDSA署名に変換します。この関数は、出力バッファoutに書き込まれた長さもoutlenに格納します。

    \return 0 署名の変換に成功した場合に返されます
    \return ECC_BAD_ARG_E いずれかの入力パラメータがNULLと評価される場合、または入力バッファがDERエンコードされたECDSA署名を保持するのに十分な大きさでない場合に返されます
    \return MP_INIT_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_READ_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_CMP_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MUL_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_ADD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_TO_E ecc_keyの処理中にエラーがある場合に返される可能性があります
    \return MP_MEM ecc_keyの処理中にエラーがある場合に返される可能性があります

    \param r 文字列として署名のR部分を含むバッファへのポインタ
    \param s 文字列として署名のS部分を含むバッファへのポインタ
    \param out DERエンコードされたECDSA署名を格納するバッファへのポインタ
    \param outlen 利用可能な出力バッファの長さ。署名をECDSA形式に正常に変換した後、バッファに書き込まれたバイト数を格納します

    _Example_
    \code
    int ret;
    ecc_key key;
    // キーを初期化し、RとSを生成

    char r[] = { Rで初期化 };
    char s[] = { Sで初期化 };
    byte sig[wc_ecc_sig_size(key)];
    // 署名サイズは2 * ECCキーサイズ + ASN.1オーバーヘッド用の約10バイトになります
    word32 sigSz = sizeof(sig);
    ret = wc_ecc_rs_to_sig(r, s, sig, &sigSz);
    if ( ret != 0) {
    	// パラメータから署名への変換エラー
    }
    \endcode

    \sa wc_ecc_sign_hash
    \sa wc_ecc_sig_size
*/

int wc_ecc_rs_to_sig(const char* r, const char* s, byte* out, word32* outlen);

/*!
    \ingroup ECC

    \brief この関数は、ECC署名の生の成分でecc_key構造体を埋めます。

    \return 0 ecc_key構造体へのインポートに成功した場合に返されます
    \return ECC_BAD_ARG_E いずれかの入力値がNULLと評価された場合に返されます
    \return MEMORY_E ecc_keyのパラメータを格納するためのスペースを初期化する際にエラーがある場合に返されます
    \return ASN_PARSE_E 入力curveNameがecc_setsで定義されていない場合に返されます
    \return MP_INIT_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_READ_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_CMP_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MUL_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_ADD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_TO_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MEM 入力パラメータの処理中にエラーがある場合に返される可能性があります

    \param key 埋めるecc_key構造体へのポインタ
    \param qx ASCII 16進文字列として基点のx成分を含むバッファへのポインタ
    \param qy ASCII 16進文字列として基点のy成分を含むバッファへのポインタ
    \param d ASCII 16進文字列として秘密鍵を含むバッファへのポインタ
    \param curveName ecc_setsにあるECC曲線名を含む文字列へのポインタ

    _Example_
    \code
    int ret;
    ecc_key key;
    wc_ecc_init(&key);

    char qx[] = { 基点のx成分で初期化 };
    char qy[] = { 基点のy成分で初期化 };
    char d[]  = { 秘密鍵で初期化 };
    ret = wc_ecc_import_raw(&key,qx, qy, d, "ECC-256");
    if ( ret != 0) {
    	// 指定された入力でキーを初期化する際のエラー
    }
    \endcode

    \sa wc_ecc_import_private_key
*/

int wc_ecc_import_raw(ecc_key* key, const char* qx, const char* qy,
                   const char* d, const char* curveName);

/*!
    \ingroup ECC

    \brief この関数は、ecc_key構造体から秘密鍵のみをエクスポートします。秘密鍵をバッファoutに格納し、このバッファに書き込まれたバイト数をoutLenに設定します。

    \return 0 秘密鍵のエクスポートに成功した場合に返されます
    \return ECC_BAD_ARG_E いずれかの入力値がNULLと評価された場合に返されます
    \return MEMORY_E ecc_keyのパラメータを格納するためのスペースを初期化する際にエラーがある場合に返されます
    \return ASN_PARSE_E 入力curveNameがecc_setsで定義されていない場合に返されます
    \return MP_INIT_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_READ_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_CMP_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_INVMOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MUL_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_ADD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MULMOD_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_TO_E 入力パラメータの処理中にエラーがある場合に返される可能性があります
    \return MP_MEM 入力パラメータの処理中にエラーがある場合に返される可能性があります

    \param key 秘密鍵をエクスポートするecc_key構造体へのポインタ
    \param out 秘密鍵を格納するバッファへのポインタ
    \param outLen outで利用可能なサイズを持つword32オブジェクトへのポインタ。秘密鍵のエクスポートに成功した後、outに書き込まれたバイト数で設定されます

    _Example_
    \code
    int ret;
    ecc_key key;
    // キーを初期化し、キーを作成

    char priv[ECC_KEY_SIZE];
    word32 privSz = sizeof(priv);
    ret = wc_ecc_export_private_only(&key, priv, &privSz);
    if ( ret != 0) {
    	// 秘密鍵のエクスポートエラー
    }
    \endcode

    \sa wc_ecc_import_private_key
*/

int wc_ecc_export_private_only(ecc_key* key, byte* out, word32* outLen);

/*!
    \ingroup ECC

    \brief ポイントをder形式にエクスポートします。

    \return 0 成功時に返されます。
    \return ECC_BAD_ARG_E curve_idxが0未満または無効な場合に返されます。また、次の場合にも返されます
    \return LENGTH_ONLY_E outLenが設定されているが他は何もない。
    \return BUFFER_E outLenが1 + 2 * カーブサイズ未満の場合に返されます。
    \return MEMORY_E メモリの割り当てに問題がある場合に返されます。

    \param curve_idx ecc_setsから使用されるカーブのインデックス。
    \param point derにエクスポートするポイント。
    \param out 出力の出力先。
    \param outLen 出力に許可される最大サイズ、出力の最終サイズの出力先

    _Example_
    \code
    int curve_idx;
    ecc_point* point;
    byte out[];
    word32 outLen;
    wc_ecc_export_point_der(curve_idx, point, out, &outLen);
    \endcode

    \sa wc_ecc_import_point_der
*/

int wc_ecc_export_point_der(const int curve_idx, ecc_point* point,
                            byte* out, word32* outLen);

/*!
    \ingroup ECC

    \brief der形式からポイントをインポートします。

    \return ECC_BAD_ARG_E いずれかの引数がnullの場合、またはinLenが偶数の場合に返されます。
    \return MEMORY_E 初期化中にエラーがある場合に返されます
    \return NOT_COMPILED_IN HAVE_COMP_KEYがtrueでなく、inが圧縮証明書の場合に返されます
    \return MP_OKAY 操作が成功しました。

    \param in ポイントをインポートするderバッファ。
    \param inLen derバッファの長さ。
    \param curve_idx カーブのインデックス。
    \param point ポイントの出力先。

    _Example_
    \code
    byte in[];
    word32 inLen;
    int curve_idx;
    ecc_point* point;
    wc_ecc_import_point_der(in, inLen, curve_idx, point);
    \endcode

    \sa wc_ecc_export_point_der
*/

int wc_ecc_import_point_der(const byte* in, word32 inLen, const int curve_idx,
                            ecc_point* point);

/*!
    \ingroup ECC

    \brief この関数は、ecc_key構造体のキーサイズをオクテット単位で返します。

    \return Given a valid key, 有効なキーが与えられた場合、キーサイズをオクテット単位で返します
    \return 0 指定されたキーがNULLの場合に返されます

    \param key キーサイズを取得するecc_key構造体へのポインタ

    _Example_
    \code
    int keySz;
    ecc_key key;
    // キーを初期化し、キーを作成
    keySz = wc_ecc_size(&key);
    if ( keySz == 0) {
    	// キーサイズの判定エラー
    }
    \endcode

    \sa wc_ecc_make_key
*/

int wc_ecc_size(ecc_key* key);

/*!
    \ingroup ECC

    \brief この関数は、ECC署名の最悪の場合のサイズを返します。これは（keySz * 2）+ SIG_HEADER_SZ + ECC_MAX_PAD_SZで与えられます。実際の署名サイズは、wc_ecc_sign_hashで計算できます。

    \return returns 最大署名サイズをオクテット単位で返します

    \param key size キーサイズ

    _Example_
    \code
    int sigSz = wc_ecc_sig_size_calc(32);
    if ( sigSz == 0) {
    	// 署名サイズの判定エラー
    }
    \endcode

    \sa wc_ecc_sign_hash
    \sa wc_ecc_sig_size
*/

int wc_ecc_sig_size_calc(int sz);


/*!
    \ingroup ECC

    \brief この関数は、ECC署名の最悪の場合のサイズを返します。これは（keySz * 2）+ SIG_HEADER_SZ + ECC_MAX_PAD_SZで与えられます。実際の署名サイズは、wc_ecc_sign_hashで計算できます。
    \return Success 有効なキーが与えられた場合、最大署名サイズをオクテット単位で返します
    \return 0 指定されたキーがNULLの場合に返されます

    \param key 署名サイズを取得するecc_key構造体へのポインタ

    _Example_
    \code
    int sigSz;
    ecc_key key;
    // キーを初期化し、キーを作成

    sigSz = wc_ecc_sig_size(&key);
    if ( sigSz == 0) {
        // 署名サイズの判定エラー
    }
    \endcode

    \sa wc_ecc_sign_hash
    \sa wc_ecc_sig_size_calc
*/

int wc_ecc_sig_size(const ecc_key* key);


/*!
    \ingroup ECC

    \brief この関数は、ECCを使用した安全なメッセージ交換を可能にするために、新しいECCコンテキストオブジェクト用のスペースを割り当てて初期化します。

    \return Success 新しいecEncCtxオブジェクトの生成に成功すると、そのオブジェクトへのポインタを返します
    \return NULL 関数が新しいecEncCtxオブジェクトの生成に失敗した場合に返されます

    \param flags これがサーバーコンテキストかクライアントコンテキストかを示します
    オプションは：REQ_RESP_CLIENTおよびREQ_RESP_SERVER
    \param rng ソルトを生成するために使用するRNGオブジェクトへのポインタ

    _Example_
    \code
    ecEncCtx* ctx;
    WC_RNG rng;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    if(ctx == NULL) {
        // 新しいecEncCtxオブジェクトの生成エラー
    }
    \endcode

    \sa wc_ecc_encrypt
    \sa wc_ecc_encrypt_ex
    \sa wc_ecc_decrypt
*/

ecEncCtx* wc_ecc_ctx_new(int flags, WC_RNG* rng);

/*!
    \ingroup ECC

    \brief この関数は、メッセージの暗号化と復号に使用されるecEncCtxオブジェクトを解放します。

    \return none 返り値なし。

    \param ctx 解放するecEncCtxオブジェクトへのポインタ

    _Example_
    \code
    ecEncCtx* ctx;
    WC_RNG rng;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    // 安全な通信を行う
    ...
    wc_ecc_ctx_free(&ctx);
    \endcode

    \sa wc_ecc_ctx_new
*/

void wc_ecc_ctx_free(ecEncCtx* ctx);

/*!
    \ingroup ECC

    \brief この関数は、新しいコンテキストオブジェクトを解放して割り当てる必要がないように、ecEncCtx構造体をリセットします。

    \return 0 ecEncCtx構造体が正常にリセットされた場合に返されます
    \return BAD_FUNC_ARG rngまたはctxのいずれかがNULLの場合に返されます
    \return RNG_FAILURE_E ECCオブジェクト用の新しいソルトを生成する際にエラーがある場合に返されます

    \param ctx リセットするecEncCtxオブジェクトへのポインタ
    \param rng 新しいソルトを生成するために使用するRNGオブジェクトへのポインタ

    _Example_
    \code
    ecEncCtx* ctx;
    WC_RNG rng;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    // 安全な通信を行う
    ...
    wc_ecc_ctx_reset(&ctx, &rng);
    // さらに安全な通信を行う
    \endcode

    \sa wc_ecc_ctx_new
*/

int wc_ecc_ctx_reset(ecEncCtx* ctx, WC_RNG* rng);  /* 割り当て/解放なしで再使用のためにリセット */

/*!
    \ingroup ECC

    \brief この関数は、wc_ecc_ctx_newの後にオプションで呼び出すことができます。ecEncCtxオブジェクトに暗号化、KDF、およびMACアルゴリズムを設定します。

    \return 0 ecEncCtxオブジェクトの情報を正常に設定した場合に返されます。
    \return BAD_FUNC_ARG 指定されたecEncCtxオブジェクトがNULLの場合に返されます。

    \param ctx 情報を設定するecEncCtxへのポインタ
    \param encAlgo 使用する暗号化アルゴリズム。
    \param kdfAlgo 使用するKDFアルゴリズム。
    \param macAlgo 使用するMACアルゴリズム。

    _Example_
    \code
    ecEncCtx* ctx;
    // ctxを初期化
    if(wc_ecc_ctx_set_algo(&ctx, ecAES_128_CTR, ecHKDF_SHA256, ecHMAC_SHA256))) {
	    // 情報設定エラー
    }
    \endcode

    \sa wc_ecc_ctx_new
*/

int wc_ecc_ctx_set_algo(ecEncCtx* ctx, byte encAlgo, byte kdfAlgo,
    byte macAlgo);

/*!
    \ingroup ECC

    \brief この関数は、ecEncCtxオブジェクトのソルトを返します。この関数は、ecEncCtxの状態がecSRV_INITまたはecCLI_INITの場合にのみ呼び出す必要があります。

    \return Success 成功時に、ecEncCtxソルトを返します
    \return NULL ecEncCtxオブジェクトがNULLの場合、またはecEncCtxの状態がecSRV_INITまたはecCLI_INITでない場合に返されます。後者の2つのケースでは、この関数はecEncCtxの状態をそれぞれecSRV_BAD_STATEまたはecCLI_BAD_STATEに設定します

    \param ctx ソルトを取得するecEncCtxオブジェクトへのポインタ

    _Example_
    \code
    ecEncCtx* ctx;
    WC_RNG rng;
    const byte* salt;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    salt = wc_ecc_ctx_get_own_salt(&ctx);
    if(salt == NULL) {
    	// ソルト取得エラー
    }
    \endcode

    \sa wc_ecc_ctx_new
    \sa wc_ecc_ctx_set_peer_salt
    \sa wc_ecc_ctx_set_kdf_salt
*/

const byte* wc_ecc_ctx_get_own_salt(ecEncCtx*);

/*!
    \ingroup ECC

    \brief この関数は、ecEncCtxオブジェクトのピアソルトを設定します。

    \return 0 ecEncCtxオブジェクトのピアソルトを正常に設定した場合に返されます。
    \return BAD_FUNC_ARG 指定されたecEncCtxオブジェクトがNULLまたは無効なプロトコルを持つ場合、または指定されたソルトがNULLの場合に返されます
    \return BAD_ENC_STATE_E ecEncCtxの状態がecSRV_SALT_GETまたはecCLI_SALT_GETの場合に返されます。後者の2つのケースでは、この関数はecEncCtxの状態をそれぞれecSRV_BAD_STATEまたはecCLI_BAD_STATEに設定します

    \param ctx ソルトを設定するecEncCtxへのポインタ
    \param salt ピアのソルトへのポインタ

    _Example_
    \code
    ecEncCtx* cliCtx, srvCtx;
    WC_RNG rng;
    const byte* cliSalt, srvSalt;
    int ret;

    wc_InitRng(&rng);
    cliCtx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    srvCtx = wc_ecc_ctx_new(REQ_RESP_SERVER, &rng);

    cliSalt = wc_ecc_ctx_get_own_salt(&cliCtx);
    srvSalt = wc_ecc_ctx_get_own_salt(&srvCtx);
    ret = wc_ecc_ctx_set_peer_salt(&cliCtx, srvSalt);
    \endcode

    \sa wc_ecc_ctx_get_own_salt
    \sa wc_ecc_ctx_set_kdf_salt
*/

int wc_ecc_ctx_set_peer_salt(ecEncCtx* ctx, const byte* salt);

/*!
    \ingroup ECC

    \brief この関数は、KDFで使用するソルトポインタと長さをecEncCtxオブジェクトに設定します。

    \return 0 ecEncCtxオブジェクトのソルトを正常に設定した場合に返されます。
    \return BAD_FUNC_ARG 指定されたecEncCtxオブジェクトがNULLの場合、または指定されたソルトがNULLで長さがNULLでない場合に返されます。

    \param ctx ソルトを設定するecEncCtxへのポインタ
    \param salt ソルトバッファへのポインタ
    \param sz ソルトの長さ（バイト単位）

    _Example_
    \code
    ecEncCtx* srvCtx;
    WC_RNG rng;
    byte cliSalt[] = { 固定ソルトデータ };
    word32 cliSaltLen = (word32)sizeof(cliSalt);
    int ret;

    wc_InitRng(&rng);
    cliCtx = wc_ecc_ctx_new(REQ_RESP_SERVER, &rng);

    ret = wc_ecc_ctx_set_kdf_salt(&cliCtx, cliSalt, cliSaltLen);
    \endcode

    \sa wc_ecc_ctx_get_own_salt
    \sa wc_ecc_ctx_get_peer_salt
*/

int wc_ecc_ctx_set_kdf_salt(ecEncCtx* ctx, const byte* salt, word32 sz);

/*!
    \ingroup ECC

    \brief この関数は、wc_ecc_ctx_set_peer_saltの前または後にオプションで呼び出すことができます。ecEncCtxオブジェクトのオプション情報を設定します。

    \return 0 ecEncCtxオブジェクトの情報を正常に設定した場合に返されます。
    \return BAD_FUNC_ARG 指定されたecEncCtxオブジェクトがNULLの場合、入力infoがNULLの場合、またはそのサイズが無効な場合に返されます

    \param ctx 情報を設定するecEncCtxへのポインタ
    \param info 設定する情報を含むバッファへのポインタ
    \param sz infoバッファのサイズ

    _Example_
    \code
    ecEncCtx* ctx;
    byte info[] = { 情報で初期化 };
    // ctxを初期化、ソルトを取得、
    if(wc_ecc_ctx_set_info(&ctx, info, sizeof(info))) {
	    // 情報設定エラー
    }
    \endcode

    \sa wc_ecc_ctx_new
*/

int wc_ecc_ctx_set_info(ecEncCtx* ctx, const byte* info, int sz);

/*!
    \ingroup ECC

    \brief この関数は、msgからoutへ指定された入力メッセージを暗号化します。この関数は、オプションのctxオブジェクトをパラメータとして受け取ります。提供された場合、暗号化はecEncCtxのencAlgo、kdfAlgo、およびmacAlgoに基づいて進行します。ctxが提供されない場合、デフォルトのアルゴリズムecAES_128_CBC、ecHKDF_SHA256、およびecHMAC_SHA256で処理が完了します。この関数では、ctxで指定された暗号化タイプに応じてメッセージがパディングされている必要があります。

    \return 0 入力メッセージの暗号化に成功した場合に返されます
    \return BAD_FUNC_ARG privKey、pubKey、msg、msgSz、out、またはoutSzがNULLの場合、またはctxオブジェクトがサポートされていない暗号化タイプを指定している場合に返されます
    \return BAD_ENC_STATE_E 指定されたctxオブジェクトが暗号化に適していない状態にある場合に返されます
    \return BUFFER_E 提供された出力バッファが暗号化された暗号文を格納するには小さすぎる場合に返されます
    \return MEMORY_E 共有秘密鍵用のメモリを割り当てる際にエラーがある場合に返されます

    \param privKey 暗号化に使用する秘密鍵を含むecc_keyオブジェクトへのポインタ
    \param pubKey 通信したいピアの公開鍵を含むecc_keyオブジェクトへのポインタ
    \param msg 暗号化するメッセージを保持するバッファへのポインタ
    \param msgSz 暗号化するバッファのサイズ
    \param out 暗号化された暗号文を格納するバッファへのポインタ
    \param outSz outバッファで利用可能なサイズを含むword32オブジェクトへのポインタ。メッセージの暗号化に成功すると、出力バッファに書き込まれたバイト数を保持します
    \param ctx オプション：使用する異なる暗号化アルゴリズムを指定するecEncCtxオブジェクトへのポインタ

    _Example_
    \code
    byte msg[] = { 暗号化するメッセージで初期化。ブロックサイズにパディングされていることを確認 };
    byte out[sizeof(msg)];
    word32 outSz = sizeof(out);
    int ret;
    ecc_key cli, serv;
    // cliを秘密鍵で初期化
    // servを受信した公開鍵で初期化

    ecEncCtx* cliCtx, servCtx;
    // cliCtxとservCtxを初期化
    // ソルトを交換
    ret = wc_ecc_encrypt(&cli, &serv, msg, sizeof(msg), out, &outSz, cliCtx);
    if(ret != 0) {
    	// メッセージの暗号化エラー
    }
    \endcode

    \sa wc_ecc_encrypt_ex
    \sa wc_ecc_decrypt
*/

int wc_ecc_encrypt(ecc_key* privKey, ecc_key* pubKey, const byte* msg,
                word32 msgSz, byte* out, word32* outSz, ecEncCtx* ctx);

/*!
    \ingroup ECC

    \brief この関数は、msgからoutへ指定された入力メッセージを暗号化します。この関数は、オプションのctxオブジェクトをパラメータとして受け取ります。提供された場合、暗号化はecEncCtxのencAlgo、kdfAlgo、およびmacAlgoに基づいて進行します。ctxが提供されない場合、デフォルトのアルゴリズムecAES_128_CBC、ecHKDF_SHA256、およびecHMAC_SHA256で処理が完了します。この関数では、ctxで指定された暗号化タイプに応じてメッセージがパディングされている必要があります。

    \return 0 入力メッセージの暗号化に成功した場合に返されます
    \return BAD_FUNC_ARG privKey、pubKey、msg、msgSz、out、またはoutSzがNULLの場合、またはctxオブジェクトがサポートされていない暗号化タイプを指定している場合に返されます
    \return BAD_ENC_STATE_E 指定されたctxオブジェクトが暗号化に適していない状態にある場合に返されます
    \return BUFFER_E 提供された出力バッファが暗号化された暗号文を格納するには小さすぎる場合に返されます
    \return MEMORY_E 共有秘密鍵用のメモリを割り当てる際にエラーがある場合に返されます

    \param privKey 暗号化に使用する秘密鍵を含むecc_keyオブジェクトへのポインタ
    \param pubKey 通信したいピアの公開鍵を含むecc_keyオブジェクトへのポインタ
    \param msg 暗号化するメッセージを保持するバッファへのポインタ
    \param msgSz 暗号化するバッファのサイズ
    \param out 暗号化された暗号文を格納するバッファへのポインタ
    \param outSz outバッファで利用可能なサイズを含むword32オブジェクトへのポインタ。メッセージの暗号化に成功すると、出力バッファに書き込まれたバイト数を保持します
    \param ctx オプション：使用する異なる暗号化アルゴリズムを指定するecEncCtxオブジェクトへのポインタ
    \param compressed 公開鍵フィールドを圧縮形式で出力する。

    _Example_
    \code
    byte msg[] = { 暗号化するメッセージで初期化。ブロックサイズにパディングされていることを確認 };
    byte out[sizeof(msg)];
    word32 outSz = sizeof(out);
    int ret;
    ecc_key cli, serv;
    // cliを秘密鍵で初期化
    // servを受信した公開鍵で初期化

    ecEncCtx* cliCtx, servCtx;
    // cliCtxとservCtxを初期化
    // ソルトを交換
    ret = wc_ecc_encrypt_ex(&cli, &serv, msg, sizeof(msg), out, &outSz, cliCtx,
        1);
    if(ret != 0) {
    	// メッセージの暗号化エラー
    }
    \endcode

    \sa wc_ecc_encrypt
    \sa wc_ecc_decrypt
*/

int wc_ecc_encrypt_ex(ecc_key* privKey, ecc_key* pubKey, const byte* msg,
    word32 msgSz, byte* out, word32* outSz, ecEncCtx* ctx, int compressed);

/*!
    \ingroup ECC

    \brief この関数は、msgからoutへ暗号文を復号します。この関数は、オプションのctxオブジェクトをパラメータとして受け取ります。提供された場合、暗号化はecEncCtxのencAlgo、kdfAlgo、およびmacAlgoに基づいて進行します。ctxが提供されない場合、デフォルトのアルゴリズムecAES_128_CBC、ecHKDF_SHA256、およびecHMAC_SHA256で処理が完了します。この関数では、ctxで指定された暗号化タイプに応じてメッセージがパディングされている必要があります。

    \return 0 入力メッセージの復号に成功した場合に返されます
    \return BAD_FUNC_ARG privKey、pubKey、msg、msgSz、out、またはoutSzがNULLの場合、またはctxオブジェクトがサポートされていない暗号化タイプを指定している場合に返されます
    \return BAD_ENC_STATE_E 指定されたctxオブジェクトが復号に適していない状態にある場合に返されます
    \return BUFFER_E 提供された出力バッファが復号された平文を格納するには小さすぎる場合に返されます
    \return MEMORY_E 共有秘密鍵用のメモリを割り当てる際にエラーがある場合に返されます

    \param privKey 復号に使用する秘密鍵を含むecc_keyオブジェクトへのポインタ
    \param pubKey 通信したいピアの公開鍵を含むecc_keyオブジェクトへのポインタ
    \param msg 復号する暗号文を保持するバッファへのポインタ
    \param msgSz 復号するバッファのサイズ
    \param out 復号された平文を格納するバッファへのポインタ
    \param outSz outバッファで利用可能なサイズを含むword32オブジェクトへのポインタ。暗号文の復号に成功すると、出力バッファに書き込まれたバイト数を保持します
    \param ctx オプション：使用する異なる復号アルゴリズムを指定するecEncCtxオブジェクトへのポインタ

    _Example_
    \code
    byte cipher[] = { 復号する暗号文で初期化。ブロックサイズにパディングされていることを確認 };
    byte plain[sizeof(cipher)];
    word32 plainSz = sizeof(plain);
    int ret;
    ecc_key cli, serv;
    // cliを秘密鍵で初期化
    // servを受信した公開鍵で初期化
    ecEncCtx* cliCtx, servCtx;
    // cliCtxとservCtxを初期化
    // ソルトを交換
    ret = wc_ecc_decrypt(&cli, &serv, cipher, sizeof(cipher),
    plain, &plainSz, cliCtx);

    if(ret != 0) {
    	// メッセージの復号エラー
    }
    \endcode

    \sa wc_ecc_encrypt
    \sa wc_ecc_encrypt_ex
*/

int wc_ecc_decrypt(ecc_key* privKey, ecc_key* pubKey, const byte* msg,
                word32 msgSz, byte* out, word32* outSz, ecEncCtx* ctx);


/*!
    \ingroup ECC

    \brief ノンブロッキング操作のためのECCサポートを有効にします。次のビルドオプションでSingle Precision（SP）数学でサポートされています：
            WOLFSSL_SP_NONBLOCK
            WOLFSSL_SP_SMALL
            WOLFSSL_SP_NO_MALLOC
            WC_ECC_NONBLOCK

    \return 0 入力メッセージのコールバックコンテキストの設定に成功した場合に返されます

    \param key ecc_keyオブジェクトへのポインタ
    \param ctx SP用のスタックデータキャッシュを持つecc_nb_ctx_t構造体へのポインタ

    _Example_
    \code
    int ret;
    ecc_key ecc;
    ecc_nb_ctx_t nb_ctx;

    ret = wc_ecc_init(&ecc);
    if (ret == 0) {
        ret = wc_ecc_set_nonblock(&ecc, &nb_ctx);
        if (ret == 0) {
            do {
                ret = wc_ecc_verify_hash_ex(
                    &r, &s,       // mp_intとしてのr/s
                    hash, hashSz, // 計算されたハッシュダイジェスト
                    &verify_res,  // 検証結果 1=成功
                    &key
                );

                // TODO: リアルタイム作業をここで呼び出すことができます
            } while (ret == FP_WOULDBLOCK);
        }
        wc_ecc_free(&key);
    }
    \endcode
*/
int wc_ecc_set_nonblock(ecc_key *key, ecc_nb_ctx_t* ctx);

/*!
    \ingroup ECC

    \brief 指定されたサイズより大きいキーを持つカーブまたはカーブIDに一致するカーブを比較し、より小さいキーサイズを持つカーブをキーに設定します。

    \return 0 キーの設定に成功した場合に返されます

    \param keysize キーサイズ（バイト単位）
    \param curve_id カーブID

                                                                                                        _Example_
    \code int ret;
    ecc_key ecc;

    ret = wc_ecc_init(&ecc);
    if (ret != 0)
        return ret;
        ret = wc_ecc_set_curve(&ecc, 32, ECC_SECP256R1));
        if (ret != 0)
            return ret;

    \endcode
*/
int wc_ecc_set_curve(ecc_key *key, int keysize, int curve_id);
