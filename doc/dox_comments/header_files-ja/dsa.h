/*!
    \ingroup DSA

    \brief この関数は、デジタル署名アルゴリズム(DSA)による認証に使用するために、DsaKeyオブジェクトを初期化します。

    \return 0 成功時に返されます。
    \return BAD_FUNC_ARG NULLキーが渡された場合に返されます。

    \param key 初期化するDsaKey構造体へのポインタ

    _Example_
    \code
    DsaKey key;
    int ret;
    ret = wc_InitDsaKey(&key); // DSA鍵を初期化
    \endcode

    \sa wc_FreeDsaKey
*/
int wc_InitDsaKey(DsaKey* key);

/*!
    \ingroup DSA

    \brief この関数は、使用後にDsaKeyオブジェクトを解放します。

    \return none 戻り値なし。

    \param key 解放するDsaKey構造体へのポインタ

    _Example_
    \code
    DsaKey key;
    // 鍵を初期化、認証に使用
    ...
    wc_FreeDsaKey(&key); // DSA鍵を解放
    \endcode

    \sa wc_FreeDsaKey
*/
void wc_FreeDsaKey(DsaKey* key);

/*!
    \ingroup DSA

    \brief この関数は、入力ダイジェストに署名し、結果を出力バッファoutに格納します。

    \return 0 入力ダイジェストへの署名に成功した場合に返されます
    \return MP_INIT_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_READ_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_CMP_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_INVMOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_EXPTMOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MUL_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_ADD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MULMOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_TO_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MEM DSA署名の処理中にエラーが発生した場合に返される可能性があります。

    \param digest 署名するハッシュへのポインタ
    \param out 署名を格納するバッファへのポインタ
    \param key 署名を生成するために使用する初期化されたDsaKey構造体へのポインタ
    \param rng 署名生成で使用する初期化されたRNGへのポインタ

    _Example_
    \code
    DsaKey key;
    // DSA鍵を初期化、秘密鍵をロード
    int ret;
    WC_RNG rng;
    wc_InitRng(&rng);
    byte hash[] = { // ハッシュダイジェストで初期化 };
    byte signature[40]; // 署名は40バイト(320ビット)になります

    ret = wc_DsaSign(hash, signature, &key, &rng);
    if (ret != 0) {
	    // DSA署名生成エラー
    }
    \endcode

    \sa wc_DsaVerify
*/
int wc_DsaSign(const byte* digest, byte* out,
                           DsaKey* key, WC_RNG* rng);

/*!
    \ingroup DSA

    \brief この関数は、秘密鍵を使用してダイジェストの署名を検証します。検証が正しく行われたかどうかをanswerパラメータに格納します。1は検証成功、0は検証失敗に対応します。

    \return 0 検証リクエストの処理に成功した場合に返されます。注意: これは署名が検証されたことを意味するのではなく、関数が成功したことのみを意味します
    \return MP_INIT_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_READ_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_CMP_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_INVMOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_EXPTMOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MUL_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_ADD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MULMOD_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_TO_E DSA署名の処理中にエラーが発生した場合に返される可能性があります。
    \return MP_MEM DSA署名の処理中にエラーが発生した場合に返される可能性があります。

    \param digest 署名の対象を含むダイジェストへのポインタ
    \param sig 検証する署名を含むバッファへのポインタ
    \param key 署名を検証するために使用する初期化されたDsaKey構造体へのポインタ
    \param answer 検証が成功したかどうかを格納する整数へのポインタ

    _Example_
    \code
    DsaKey key;
    // DSA鍵を初期化、公開鍵をロード

    int ret;
    int verified;
    byte hash[] = { // ハッシュダイジェストで初期化 };
    byte signature[] = { // 検証する署名で初期化 };
    ret = wc_DsaVerify(hash, signature, &key, &verified);
    if (ret != 0) {
    	// 検証リクエストの処理エラー
    } else if (answer == 0) {
    	// 無効な署名
    }
    \endcode

    \sa wc_DsaSign
*/
int wc_DsaVerify(const byte* digest, const byte* sig,
                             DsaKey* key, int* answer);

/*!
    \ingroup DSA

    \brief この関数は、DSA公開鍵を含むDERフォーマットの証明書バッファをデコードし、与えられたDsaKey構造体に鍵を格納します。また、読み取られた入力の長さに応じてinOutIdxパラメータを設定します。

    \return 0 DsaKeyオブジェクトの公開鍵の設定に成功した場合に返されます
    \return ASN_PARSE_E 証明書バッファの読み取り中にエンコーディングエラーがある場合に返されます
    \return ASN_DH_KEY_E DSAパラメータの1つが正しくフォーマットされていない場合に返されます

    \param input DERフォーマットのDSA公開鍵を含むバッファへのポインタ
    \param inOutIdx 読み取られた証明書の最終インデックスを格納する整数へのポインタ
    \param key 公開鍵を格納するDsaKey構造体へのポインタ
    \param inSz 入力バッファのサイズ

    _Example_
    \code
    int ret, idx=0;

    DsaKey key;
    wc_InitDsaKey(&key);
    byte derBuff[] = { // DSA公開鍵};
    ret = wc_DsaPublicKeyDecode(derBuff, &idx, &key, inSz);
    if (ret != 0) {
    	// 公開鍵の読み取りエラー
    }
    \endcode

    \sa wc_InitDsaKey
    \sa wc_DsaPrivateKeyDecode
*/
int wc_DsaPublicKeyDecode(const byte* input, word32* inOutIdx,
                                      DsaKey* key, word32 inSz);

/*!
    \ingroup DSA

    \brief この関数は、DSA秘密鍵を含むDERフォーマットの証明書バッファをデコードし、与えられたDsaKey構造体に鍵を格納します。また、読み取られた入力の長さに応じてinOutIdxパラメータを設定します。

    \return 0 DsaKeyオブジェクトの秘密鍵の設定に成功した場合に返されます
    \return ASN_PARSE_E 証明書バッファの読み取り中にエンコーディングエラーがある場合に返されます
    \return ASN_DH_KEY_E DSAパラメータの1つが正しくフォーマットされていない場合に返されます

    \param input DERフォーマットのDSA秘密鍵を含むバッファへのポインタ
    \param inOutIdx 読み取られた証明書の最終インデックスを格納する整数へのポインタ
    \param key 秘密鍵を格納するDsaKey構造体へのポインタ
    \param inSz 入力バッファのサイズ

    _Example_
    \code
    int ret, idx=0;

    DsaKey key;
    wc_InitDsaKey(&key);
    byte derBuff[] = { // DSA秘密鍵 };
    ret = wc_DsaPrivateKeyDecode(derBuff, &idx, &key, inSz);
    if (ret != 0) {
    	// 秘密鍵の読み取りエラー
    }
    \endcode

    \sa wc_InitDsaKey
    \sa wc_DsaPublicKeyDecode
*/
int wc_DsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
                                       DsaKey* key, word32 inSz);

/*!
    \ingroup DSA

    \brief DsaKey鍵をDERフォーマットに変換し、output(inLen)に書き込み、書き込まれたバイト数を返します。

    \return outLen 成功、書き込まれたバイト数
    \return BAD_FUNC_ARG keyまたはoutputがnullまたはkey->typeがDSA_PRIVATEでない場合。
    \return MEMORY_E メモリ割り当てエラー。

    \param key 変換するDsaKey構造体へのポインタ。
    \param output 変換された鍵用の出力バッファへのポインタ。
    \param inLen 鍵入力の長さ。

    _Example_
    \code
    DsaKey key;
    WC_RNG rng;
    int derSz;
    int bufferSize = // 十分なバッファサイズ;
    byte der[bufferSize];

    wc_InitDsaKey(&key);
    wc_InitRng(&rng);
    wc_MakeDsaKey(&rng, &key);
    derSz = wc_DsaKeyToDer(&key, der, bufferSize);
    \endcode

    \sa wc_InitDsaKey
    \sa wc_FreeDsaKey
    \sa wc_MakeDsaKey
*/
int wc_DsaKeyToDer(DsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup DSA

    \brief DSA鍵を作成します。

    \return MP_OKAY 成功
    \return BAD_FUNC_ARG rngまたはdsaがnullの場合。
    \return MEMORY_E バッファ用のメモリを割り当てられませんでした。
    \return MP_INIT_E mp_intの初期化エラー

    \param rng WC_RNG構造体へのポインタ。
    \param dsa DsaKey構造体へのポインタ。

    _Example_
    \code
    WC_RNG rng;
    DsaKey dsa;
    wc_InitRng(&rng);
    wc_InitDsa(&dsa);
    if(wc_MakeDsaKey(&rng, &dsa) != 0)
    {
        // 鍵作成エラー
    }
    \endcode

    \sa wc_InitDsaKey
    \sa wc_FreeDsaKey
    \sa wc_DsaSign
*/
int wc_MakeDsaKey(WC_RNG *rng, DsaKey *dsa);

/*!
    \ingroup DSA

    \brief FIPS 186-4は、modulus_size値として(1024, 160) (2048, 256) (3072, 256)を有効と定義しています

    \return 0 成功
    \return BAD_FUNC_ARG rngまたはdsaがnullまたはmodulus_sizeが無効な場合。
    \return MEMORY_E メモリ割り当て試行エラー。

    \param rng wolfCrypt rngへのポインタ。
    \param modulus_size 1024、2048、または3072が有効な値です。
    \param dsa DsaKey構造体へのポインタ。

    _Example_
    \code
    DsaKey key;
    WC_RNG rng;
    wc_InitDsaKey(&key);
    wc_InitRng(&rng);
    if(wc_MakeDsaParameters(&rng, 1024, &genKey) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_MakeDsaKey
    \sa wc_DsaKeyToDer
    \sa wc_InitDsaKey
*/
int wc_MakeDsaParameters(WC_RNG *rng, int modulus_size, DsaKey *dsa);