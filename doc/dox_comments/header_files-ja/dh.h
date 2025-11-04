/*!
    \ingroup Diffie-Hellman

    \brief この関数は、Diffie-Hellman鍵交換プロトコルで安全な秘密鍵をネゴシエートするために使用するDiffie-Hellman鍵を初期化します。

    \return none 戻り値なし。

    \param key 安全な鍵交換で使用するために初期化するDhKey構造体へのポインタ

    _Example_
    \code
    DhKey key;
    wc_InitDhKey(&key); // DH鍵を初期化
    \endcode

    \sa wc_FreeDhKey
    \sa wc_DhGenerateKeyPair
*/
int wc_InitDhKey(DhKey* key);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は、Diffie-Hellman鍵交換プロトコルで安全な秘密鍵をネゴシエートするために使用された後、Diffie-Hellman鍵を解放します。

    \return none 戻り値なし。

    \param key 解放するDhKey構造体へのポインタ

    _Example_
    \code
    DhKey key;
    // 鍵を初期化、鍵交換を実行

    wc_FreeDhKey(&key); // メモリリークを避けるためにDH鍵を解放
    \endcode

    \sa wc_InitDhKey
*/
void wc_FreeDhKey(DhKey* key);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は、Diffie-Hellman公開パラメータに基づいて公開/秘密鍵ペアを生成し、秘密鍵をprivに、公開鍵をpubに格納します。初期化されたDiffie-Hellman鍵と初期化されたrng構造体を受け取ります。

    \return BAD_FUNC_ARG この関数への入力の1つを解析する際にエラーがある場合に返されます
    \return RNG_FAILURE_E rngを使用して乱数を生成する際にエラーがある場合に返されます
    \return MP_INIT_E 公開鍵を生成する際に数学ライブラリでエラーがある場合に返される可能性があります
    \return MP_READ_E 公開鍵を生成する際に数学ライブラリでエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E 公開鍵を生成する際に数学ライブラリでエラーがある場合に返される可能性があります
    \return MP_TO_E 公開鍵を生成する際に数学ライブラリでエラーがある場合に返される可能性があります

    \param key 鍵ペアを生成するDhKey構造体へのポインタ
    \param rng 鍵を生成するために使用する初期化された乱数生成器(rng)へのポインタ
    \param priv 秘密鍵を格納するバッファへのポインタ
    \param privSz privに書き込まれた秘密鍵のサイズを格納します
    \param pub 公開鍵を格納するバッファへのポインタ
    \param pubSz pubに書き込まれた秘密鍵のサイズを格納します

    _Example_
    \code
    DhKey key;
    int ret;
    byte priv[256];
    byte pub[256];
    word32 privSz, pubSz;

    wc_InitDhKey(&key); // 鍵を初期化
    // wc_DhSetKeyまたはwc_DhKeyDecodeを使用してDHパラメータを設定
    WC_RNG rng;
    wc_InitRng(&rng); // rngを初期化
    ret = wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
    \endcode

    \sa wc_InitDhKey
    \sa wc_DhSetKey
    \sa wc_DhKeyDecode
*/
int wc_DhGenerateKeyPair(DhKey* key, WC_RNG* rng, byte* priv,
                                 word32* privSz, byte* pub, word32* pubSz);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は、ローカル秘密鍵と受信した公開鍵に基づいて合意された秘密鍵を生成します。交換の両側で完了すると、この関数は対称通信用の合意された秘密鍵を生成します。共有秘密鍵の生成に成功すると、書き込まれた秘密鍵のサイズがagreeSzに格納されます。

    \return 0 合意された秘密鍵の生成に成功した場合に返されます
    \return MP_INIT_E 共有秘密鍵の生成中にエラーがある場合に返される可能性があります
    \return MP_READ_E 共有秘密鍵の生成中にエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E 共有秘密鍵の生成中にエラーがある場合に返される可能性があります
    \return MP_TO_E 共有秘密鍵の生成中にエラーがある場合に返される可能性があります

    \param key 共有鍵を計算するために使用するDhKey構造体へのポインタ
    \param agree 秘密鍵を格納するバッファへのポインタ
    \param agreeSz 生成成功後に秘密鍵のサイズを保持します
    \param priv ローカル秘密鍵を含むバッファへのポインタ
    \param privSz ローカル秘密鍵のサイズ
    \param otherPub 受信した公開鍵を含むバッファへのポインタ
    \param pubSz 受信した公開鍵のサイズ

    _Example_
    \code
    DhKey key;
    int ret;
    byte priv[256];
    byte agree[256];
    word32 agreeSz;

    // 鍵を初期化、鍵素数とベースを設定
    // wc_DhGenerateKeyPair -- 秘密鍵をprivに格納
    byte pub[] = { // 受信した公開鍵で初期化 };
    ret = wc_DhAgree(&key, agree, &agreeSz, priv, sizeof(priv), pub,
    sizeof(pub));
    if ( ret != 0 ) {
    	// 共有鍵生成エラー
    }
    \endcode

    \sa wc_DhGenerateKeyPair
*/
int wc_DhAgree(DhKey* key, byte* agree, word32* agreeSz,
                       const byte* priv, word32 privSz, const byte* otherPub,
                       word32 pubSz);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は、DERフォーマットの鍵を含む指定された入力バッファからDiffie-Hellman鍵をデコードします。結果をDhKey構造体に格納します。

    \return 0 入力鍵のデコードに成功した場合に返されます
    \return ASN_PARSE_E 入力のシーケンスを解析する際にエラーがある場合に返されます
    \return ASN_DH_KEY_E 解析された入力から秘密鍵パラメータを読み取る際にエラーがある場合に返されます

    \param input DERフォーマットのDiffie-Hellman鍵を含むバッファへのポインタ
    \param inOutIdx 鍵をデコードする際に解析されたインデックスを格納する整数へのポインタ
    \param key 入力鍵で初期化するDhKey構造体へのポインタ
    \param inSz 入力バッファの長さ。読み取り可能な最大長を示します

    _Example_
    \code
    DhKey key;
    word32 idx = 0;

    byte keyBuff[1024];
    // DERフォーマットの鍵で初期化
    wc_DhKeyInit(&key);
    ret = wc_DhKeyDecode(keyBuff, &idx, &key, sizeof(keyBuff));

    if ( ret != 0 ) {
    	// 鍵のデコードエラー
    }
    \endcode

    \sa wc_DhSetKey
*/
int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key,
                           word32);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は、入力秘密鍵パラメータを使用してDhKey構造体の鍵を設定します。wc_DhKeyDecodeとは異なり、この関数は入力鍵がDERフォーマットでフォーマットされている必要はなく、代わりに単純に解析された入力パラメータp(素数)とg(ベース)を受け入れます。

    \return 0 鍵の設定に成功した場合に返されます
    \return BAD_FUNC_ARG 入力パラメータのいずれかがNULLと評価される場合に返されます
    \return MP_INIT_E 格納用の鍵パラメータを初期化する際にエラーがある場合に返されます
    \return ASN_DH_KEY_E DH鍵パラメータpとgを読み取る際にエラーがある場合に返されます

    \param key 鍵を設定するDhKey構造体へのポインタ
    \param p 鍵で使用する素数を含むバッファへのポインタ
    \param pSz 入力素数の長さ
    \param g 鍵で使用するベースを含むバッファへのポインタ
    \param gSz 入力ベースの長さ

    _Example_
    \code
    DhKey key;

    byte p[] = { // 素数で初期化 };
    byte g[] = { // ベースで初期化 };
    wc_DhKeyInit(&key);
    ret = wc_DhSetKey(key, p, sizeof(p), g, sizeof(g));

    if ( ret != 0 ) {
    	// 鍵設定エラー
    }
    \endcode

    \sa wc_DhKeyDecode
*/
int wc_DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g,
                        word32 gSz);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は、指定された入力バッファからDERフォーマットのDiffie-Hellmanパラメータp(素数)とg(ベース)をロードします。

    \return 0 DHパラメータの抽出に成功した場合に返されます
    \return ASN_PARSE_E DERフォーマットのDH証明書を解析する際にエラーが発生した場合に返されます
    \return BUFFER_E pまたはgに解析されたパラメータを格納する十分なスペースがない場合に返されます

    \param input 解析するDERフォーマットのDiffie-Hellman証明書を含むバッファへのポインタ
    \param inSz 入力バッファのサイズ
    \param p 解析された素数を格納するバッファへのポインタ
    \param pInOutSz pバッファで利用可能なサイズを含むword32オブジェクトへのポインタ。関数呼び出しの完了後、バッファに書き込まれたバイト数で上書きされます
    \param g 解析されたベースを格納するバッファへのポインタ
    \param gInOutSz gバッファで利用可能なサイズを含むword32オブジェクトへのポインタ。関数呼び出しの完了後、バッファに書き込まれたバイト数で上書きされます

    _Example_
    \code
    byte dhCert[] = { DERフォーマットの証明書で初期化 };
    byte p[MAX_DH_SIZE];
    byte g[MAX_DH_SIZE];
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;

    ret = wc_DhParamsLoad(dhCert, sizeof(dhCert), p, &pSz, g, &gSz);
    if ( ret != 0 ) {
    	// 入力の解析エラー
    }
    \endcode

    \sa wc_DhSetKey
    \sa wc_DhKeyDecode
*/
int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p,
                            word32* pInOutSz, byte* g, word32* gInOutSz);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は...を返し、HAVE_FFDHE_2048が定義されている必要があります。

    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe6144_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe2048_Get(void);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は...を返し、HAVE_FFDHE_3072が定義されている必要があります。

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe6144_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe3072_Get(void);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は...を返し、HAVE_FFDHE_4096が定義されている必要があります。

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe6144_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe4096_Get(void);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は...を返し、HAVE_FFDHE_6144が定義されている必要があります。

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe6144_Get(void);

/*!
    \ingroup Diffie-Hellman

    \brief この関数は...を返し、HAVE_FFDHE_8192が定義されている必要があります。

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe6144_Get
*/
const DhParams* wc_Dh_ffdhe8192_Get(void);

/*!
    \ingroup Diffie-Hellman

    \brief FFCのSP 800-56Ar3、セクション5.6.2.1.4、メソッド(b)のプロセスに従って、DH鍵のペアワイズ整合性をチェックします。
*/
int wc_DhCheckKeyPair(DhKey* key, const byte* pub, word32 pubSz,
                        const byte* priv, word32 privSz);

/*!
    \ingroup Diffie-Hellman

    \brief 無効な数値についてDH秘密鍵をチェックします
*/
int wc_DhCheckPrivKey(DhKey* key, const byte* priv, word32 pubSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhCheckPrivKey_ex(DhKey* key, const byte* priv, word32 pubSz,
                            const byte* prime, word32 primeSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhCheckPubKey(DhKey* key, const byte* pub, word32 pubSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhCheckPubKey_ex(DhKey* key, const byte* pub, word32 pubSz,
                            const byte* prime, word32 primeSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhExportParamsRaw(DhKey* dh, byte* p, word32* pSz,
                       byte* q, word32* qSz, byte* g, word32* gSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhGenerateParams(WC_RNG *rng, int modSz, DhKey *dh);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhSetCheckKey(DhKey* key, const byte* p, word32 pSz,
                        const byte* g, word32 gSz, const byte* q, word32 qSz,
                        int trusted, WC_RNG* rng);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhSetKey_ex(DhKey* key, const byte* p, word32 pSz,
                        const byte* g, word32 gSz, const byte* q, word32 qSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_FreeDhKey(DhKey* key);