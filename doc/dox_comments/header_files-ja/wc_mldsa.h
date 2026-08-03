/*!
    \ingroup ML_DSA

    \brief wc_MlDsaKeyオブジェクトを初期化します。他のML-DSA操作を行う前に呼び出さなければなりません。使用が終わったらwc_MlDsaKey_Free()でリソースを解放してください。

    ML-DSA(FIPS 204)は耐量子のデジタル署名アルゴリズムです。3つのパラメータセットが定義されており、初期化後にwc_MlDsaKey_SetParams()で選択します。
      - WC_ML_DSA_44(NISTセキュリティレベル2)
      - WC_ML_DSA_65(レベル3)
      - WC_ML_DSA_87(レベル5)

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key 初期化するwc_MlDsaKeyへのポインタ。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId ハードウェア暗号コールバック用のデバイス識別子。ソフトウェアのみで処理する場合はINVALID_DEVIDを使用します。

    _Example_
    \code
    wc_MlDsaKey key;
    int ret;

    ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // 鍵の初期化エラー
    }
    ret = wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65);
    // ... 鍵を使用 ...
    wc_MlDsaKey_Free(&key);
    \endcode

    \sa wc_MlDsaKey_Free
    \sa wc_MlDsaKey_SetParams
    \sa wc_MlDsaKey_MakeKey
*/
int wc_MlDsaKey_Init(wc_MlDsaKey* key, void* heap, int devId);

/*!
    \ingroup ML_DSA

    \brief 新しいwc_MlDsaKeyをヒープ上に確保して初期化します。返されたポインタはwc_MlDsaKey_Delete()で解放しなければなりません。wolfSSLがWC_NO_CONSTRUCTORSを指定せずにビルドされている場合にのみ利用できます。

    \return 成功した場合、新しく確保されたwc_MlDsaKeyへのポインタを返します。
    \return NULL メモリ確保に失敗した場合に返されます。

    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId ハードウェア暗号コールバック用のデバイス識別子。ソフトウェアのみで処理する場合はINVALID_DEVIDを使用します。

    _Example_
    \code
    wc_MlDsaKey* key = wc_MlDsaKey_New(NULL, INVALID_DEVID);
    if (key == NULL) {
        // メモリ確保に失敗
    }
    // ... 鍵を使用 ...
    wc_MlDsaKey_Delete(key, &key);
    \endcode

    \sa wc_MlDsaKey_Delete
    \sa wc_MlDsaKey_Init
*/
wc_MlDsaKey* wc_MlDsaKey_New(void* heap, int devId);

/*!
    \ingroup ML_DSA

    \brief wc_MlDsaKey_New()が返したヒープ上のwc_MlDsaKeyをゼロクリアして解放します。成功時、key_pがNULLでない場合はkey_pを介して呼び出し側のポインタ変数にNULLが設定されます。wolfSSLがWC_NO_CONSTRUCTORSを指定せずにビルドされている場合にのみ利用できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key 解放するwc_MlDsaKey。
    \param [in,out] key_p 呼び出し側のポインタ変数のアドレス(省略可)。NULLでない場合、成功時にNULLが設定されます。

    \sa wc_MlDsaKey_New
*/
int wc_MlDsaKey_Delete(wc_MlDsaKey* key, wc_MlDsaKey** key_p);

/*!
    \ingroup ML_DSA

    \brief デバイス側の鍵識別子を指定してwc_MlDsaKeyを初期化します。wc_MlDsaKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるバイナリ形式のidも保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    idは鍵オブジェクトへコピーされます。呼び出し側はこの関数から戻った直後に自身のバッファを解放して構いません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。
    \return BUFFER_E lenが負の場合、またはMLDSA_MAX_ID_LENを超える場合に返されます。

    \param [in,out] key 初期化するwc_MlDsaKeyへのポインタ。
    \param [in] id デバイス側の鍵識別子バイト列へのポインタ。lenが0の場合はNULLでも構いません。
    \param [in] len idのバイト数。[0, MLDSA_MAX_ID_LEN]の範囲内でなければなりません。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId 暗号コールバック用のデバイス識別子。INVALID_DEVIDではなく、登録済みのコールバックのdevIdを指定してください。

    \sa wc_MlDsaKey_Init
    \sa wc_MlDsaKey_InitLabel
    \sa wc_MlDsaKey_Free
*/
int wc_MlDsaKey_InitId(wc_MlDsaKey* key, const unsigned char* id, int len,
    void* heap, int devId);

/*!
    \ingroup ML_DSA

    \brief デバイス側の鍵ラベルを指定してwc_MlDsaKeyを初期化します。wc_MlDsaKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるラベル文字列も保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    ラベルの長さはXSTRLENで取得されるため、途中にNULバイトが含まれるとそこでラベルが終端します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlabelがNULLの場合に返されます。
    \return BUFFER_E labelが空の場合、またはMLDSA_MAX_LABEL_LENより長い場合に返されます。

    \param [in,out] key 初期化するwc_MlDsaKeyへのポインタ。
    \param [in] label NUL終端されたデバイス側の鍵ラベル文字列。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId 暗号コールバック用のデバイス識別子。

    \sa wc_MlDsaKey_Init
    \sa wc_MlDsaKey_InitId
    \sa wc_MlDsaKey_Free
*/
int wc_MlDsaKey_InitLabel(wc_MlDsaKey* key, const char* label, void* heap,
    int devId);

/*!
    \ingroup ML_DSA

    \brief この鍵に使用するML-DSAのパラメータセットを選択します。wc_MlDsaKey_Init()の後、鍵生成・署名・検証を行う前に呼び出さなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、またはlevelが認識できるパラメータセットでない場合に返されます。
    \return NOT_COMPILED_IN levelがビルド時に無効化されたパラメータセットを指している場合に返されます。

    \param [in,out] key 初期化済みのwc_MlDsaKeyへのポインタ。
    \param [in] level パラメータセット。WC_ML_DSA_44、WC_ML_DSA_65、WC_ML_DSA_87のいずれか。

    \sa wc_MlDsaKey_GetParams
    \sa wc_MlDsaKey_Init
*/
int wc_MlDsaKey_SetParams(wc_MlDsaKey* key, byte level);

/*!
    \ingroup ML_DSA

    \brief この鍵に現在設定されているML-DSAのパラメータセットを取得します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlevelがNULLの場合に返されます。

    \param [in] key 初期化済みのwc_MlDsaKeyへのポインタ。
    \param [out] level WC_ML_DSA_44、WC_ML_DSA_65、WC_ML_DSA_87のいずれかを受け取ります。

    \sa wc_MlDsaKey_SetParams
*/
int wc_MlDsaKey_GetParams(wc_MlDsaKey* key, byte* level);

/*!
    \ingroup ML_DSA

    \brief wc_MlDsaKeyが保持しているリソースを解放します。この呼び出しの後、オブジェクトを再度使用するにはwc_MlDsaKey_Init()で再初期化しなければなりません。NULLポインタを渡しても安全です。

    \param [in,out] key 解放するwc_MlDsaKeyへのポインタ。

    \sa wc_MlDsaKey_Init
*/
void wc_MlDsaKey_Free(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief 指定されたRNGを使用して新しいML-DSA鍵ペアを生成します。事前にwc_MlDsaKey_SetParams()でパラメータセットが設定されていなければなりません。成功時には公開鍵と秘密鍵の両方の要素が設定されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはrngがNULLの場合に返されます。
    \return MEMORY_E メモリ確保に失敗した場合に返されます。

    \param [in,out] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    _Example_
    \code
    wc_MlDsaKey key;
    WC_RNG rng;

    wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65);
    wc_InitRng(&rng);

    if (wc_MlDsaKey_MakeKey(&key, &rng) != 0) {
        // 鍵ペアの生成エラー
    }
    \endcode

    \sa wc_MlDsaKey_MakeKeyFromSeed
    \sa wc_MlDsaKey_SetParams
*/
int wc_MlDsaKey_MakeKey(wc_MlDsaKey* key, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief 32バイトのシードからML-DSA鍵ペアを決定的に生成します。既知解テストや、シードを別の秘密から導出するアプリケーションで有用です。seedバッファはちょうど32バイトを保持していなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはseedがNULLの場合に返されます。

    \param [in,out] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [in] seed 32バイトのシードバッファへのポインタ。

    \sa wc_MlDsaKey_MakeKey
*/
int wc_MlDsaKey_MakeKeyFromSeed(wc_MlDsaKey* key, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief FIPS 204のコンテキスト付きランダム化署名APIを使用して、ML-DSAでメッセージに署名します。空のコンテキストを使用する場合はctx=NULL、ctxLen=0を渡してください。

    呼び出し時、*sigLenはsigバッファのサイズを表します。成功時には書き込まれたバイト数に更新されます。必要なバッファサイズはwc_MlDsaKey_SigSize()またはwc_MlDsaKey_GetSigLen()で取得できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはctxLenが無効な場合に返されます。
    \return BUFFER_E sigバッファが小さすぎる場合に返されます。

    \param [in,out] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列(省略可。ctxLen=0の場合はNULLでも構いません)。
    \param [in] ctxLen ctxのバイト単位の長さ。ctxがNULLの場合は0でなければならず、255以下でなければなりません。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigLen 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] msg 署名するメッセージ。
    \param [in] msgLen msgのバイト単位の長さ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    \sa wc_MlDsaKey_VerifyCtx
    \sa wc_MlDsaKey_SignCtxWithSeed
    \sa wc_MlDsaKey_SignCtxHash
*/
int wc_MlDsaKey_SignCtx(wc_MlDsaKey* key, const byte* ctx, byte ctxLen,
    byte* sig, word32* sigLen, const byte* msg, word32 msgLen, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief HashML-DSAの署名バリアントです。事前にハッシュされたメッセージに署名します。呼び出し側がハッシュ値のバイト列を渡し、ハッシュアルゴリズムを指定します。これはFIPS 204の「事前ハッシュ」モードです。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、ctxLenが無効な場合、またはhashAlgがサポートされていない場合に返されます。
    \return BUFFER_E sigバッファが小さすぎる場合に返されます。

    \param [in,out] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列(省略可。ctxLen=0の場合はNULL)。
    \param [in] ctxLen ctxのバイト単位の長さ。255以下でなければなりません。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigLen 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] hash 署名するメッセージダイジェスト。
    \param [in] hashLen hashのバイト単位の長さ。
    \param [in] hashAlg ハッシュアルゴリズム識別子(例: WC_HASH_TYPE_SHA256)。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_VerifyCtxHash
*/
int wc_MlDsaKey_SignCtxHash(wc_MlDsaKey* key, const byte* ctx, byte ctxLen,
    byte* sig, word32* sigLen, const byte* hash, word32 hashLen,
    int hashAlg, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief コンテキストパラメータを持たない旧来のML-DSA署名APIです。wolfSSLがWOLFSSL_MLDSA_NO_CTXを有効にしてビルドされている場合にのみ利用できます。新しいコードでは、FIPS 204に準拠した空コンテキストの署名を得るために、ctx=NULL、ctxLen=0でwc_MlDsaKey_SignCtx()を呼び出してください。

    \return wc_MlDsaKey_SignCtx()を参照してください。

    \param [in,out] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigLen 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] msg 署名するメッセージ。
    \param [in] msgLen msgのバイト単位の長さ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_Verify
*/
int wc_MlDsaKey_Sign(wc_MlDsaKey* key, byte* sig, word32* sigLen,
    const byte* msg, word32 msgLen, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief wc_MlDsaKey_SignCtx()の決定的な署名バリアントです。32バイトのシードがRNGから供給される乱数を置き換えるため、同じkey/ctx/msg/seedの組み合わせからは常に同じ署名が生成されます。

    \return wc_MlDsaKey_SignCtx()を参照してください。

    \param [in,out] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列(省略可。ctxLen=0の場合はNULL)。
    \param [in] ctxLen ctxの長さ。255以下でなければなりません。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigLen 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] msg 署名するメッセージ。
    \param [in] msgLen msgのバイト単位の長さ。
    \param [in] seed 32バイトのシードバイト列。

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_SignCtxHashWithSeed
*/
int wc_MlDsaKey_SignCtxWithSeed(wc_MlDsaKey* key, const byte* ctx, byte ctxLen,
    byte* sig, word32* sigLen, const byte* msg, word32 msgLen,
    const byte* seed);

/*!
    \ingroup ML_DSA

    \brief 決定的なHashML-DSA署名です。wc_MlDsaKey_SignCtxHash()と同様ですが、RNGの代わりに与えられた32バイトのシードを使用します。

    \return wc_MlDsaKey_SignCtxHash()を参照してください。

    \param [in,out] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列(省略可。ctxLen=0の場合はNULL)。
    \param [in] ctxLen ctxの長さ。255以下でなければなりません。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigLen 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] hash 署名するメッセージダイジェスト。
    \param [in] hashLen hashのバイト単位の長さ。
    \param [in] hashAlg ハッシュアルゴリズム識別子。
    \param [in] seed 32バイトのシードバイト列。

    \sa wc_MlDsaKey_SignCtxHash
*/
int wc_MlDsaKey_SignCtxHashWithSeed(wc_MlDsaKey* key, const byte* ctx,
    byte ctxLen, byte* sig, word32* sigLen, const byte* hash,
    word32 hashLen, int hashAlg, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief 決定的な32バイトのシードを使用して、事前に計算されたmu値(FIPS 204に従って外部で導出された(tr || ctx || msg)のSHAKE256ハッシュ)に署名します。メッセージのハッシュ処理と署名処理を分離する必要があるプロトコルで使用されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはmuLenが64でない場合に返されます。
    \return BUFFER_E sigバッファが小さすぎる場合に返されます。

    \param [in,out] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigLen 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] mu 64バイトのmu値(SHAKE256の出力)。
    \param [in] muLen muの長さ。64でなければなりません。
    \param [in] seed 32バイトのシードバイト列。

    \sa wc_MlDsaKey_VerifyMu
*/
int wc_MlDsaKey_SignMuWithSeed(wc_MlDsaKey* key, byte* sig, word32* sigLen,
    const byte* mu, word32 muLen, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief コンテキストパラメータを持たない旧来のシードベース署名APIです。wolfSSLがWOLFSSL_MLDSA_NO_CTXを有効にしてビルドされている場合にのみ利用できます。新しいコードではwc_MlDsaKey_SignCtxWithSeed()を使用してください。

    \return wc_MlDsaKey_SignCtxWithSeed()を参照してください。

    \param [in,out] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigLen 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] msg 署名するメッセージ。
    \param [in] msgLen msgのバイト単位の長さ。
    \param [in] seed 32バイトのシードバイト列。

    \sa wc_MlDsaKey_SignCtxWithSeed
*/
int wc_MlDsaKey_SignWithSeed(wc_MlDsaKey* key, byte* sig, word32* sigLen,
    const byte* msg, word32 msgLen, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief wc_MlDsaKey_SignCtx()またはそのバリアントが生成したML-DSA署名を検証します。呼び出し時にresは0に設定され、署名が有効な場合は1に設定されます。それ以外の場合は0のままです。この関数の戻り値は検証処理を実行できたかどうかを示すものであり、署名が不正であること自体は関数レベルのエラーではありません。

    \return 0 検証処理が完了した場合に返されます(結果はresを確認してください)。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはctxLenが無効な場合に返されます。

    \param [in,out] key 公開鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] sig 検証する署名バイト列。
    \param [in] sigLen sigのバイト単位の長さ。
    \param [in] ctx コンテキスト文字列(省略可。ctxLen=0の場合はNULL)。
    \param [in] ctxLen ctxの長さ。255以下でなければなりません。
    \param [in] msg 署名対象であったメッセージ。
    \param [in] msgLen msgのバイト単位の長さ。
    \param [out] res 署名が有効な場合は1、それ以外の場合は0が設定されます。

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_VerifyCtxHash
    \sa wc_MlDsaKey_VerifyMu
*/
int wc_MlDsaKey_VerifyCtx(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* ctx, byte ctxLen, const byte* msg, word32 msgLen, int* res);

/*!
    \ingroup ML_DSA

    \brief メッセージダイジェストが直接渡されたHashML-DSA署名を検証します。resの意味についてはwc_MlDsaKey_VerifyCtx()を参照してください。

    \return 0 検証処理が完了した場合に返されます(結果はresを確認してください)。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、ctxLenが無効な場合、またはhashAlgがサポートされていない場合に返されます。

    \param [in,out] key 公開鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] sig 検証する署名バイト列。
    \param [in] sigLen sigのバイト単位の長さ。
    \param [in] ctx コンテキスト文字列(省略可。ctxLen=0の場合はNULL)。
    \param [in] ctxLen ctxの長さ。255以下でなければなりません。
    \param [in] hash 署名対象であったメッセージダイジェスト。
    \param [in] hashLen hashのバイト単位の長さ。
    \param [in] hashAlg ハッシュアルゴリズム識別子。
    \param [out] res 署名が有効な場合は1、それ以外の場合は0が設定されます。

    \sa wc_MlDsaKey_SignCtxHash
    \sa wc_MlDsaKey_VerifyCtx
*/
int wc_MlDsaKey_VerifyCtxHash(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* ctx, byte ctxLen, const byte* hash, word32 hashLen,
    int hashAlg, int* res);

/*!
    \ingroup ML_DSA

    \brief 事前に計算された64バイトのmu値に対する署名を検証します(wc_MlDsaKey_SignMuWithSeed()を参照)。resの意味についてはwc_MlDsaKey_VerifyCtx()を参照してください。

    \return 0 検証処理が完了した場合に返されます(結果はresを確認してください)。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはmuLenが64でない場合に返されます。

    \param [in,out] key 公開鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] sig 検証する署名バイト列。
    \param [in] sigLen sigのバイト単位の長さ。
    \param [in] mu 64バイトのmu値。
    \param [in] muLen muの長さ。64でなければなりません。
    \param [out] res 署名が有効な場合は1、それ以外の場合は0が設定されます。

    \sa wc_MlDsaKey_SignMuWithSeed
*/
int wc_MlDsaKey_VerifyMu(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* mu, word32 muLen, int* res);

/*!
    \ingroup ML_DSA

    \brief コンテキストパラメータを持たない旧来のML-DSA検証APIです。wolfSSLがWOLFSSL_MLDSA_NO_CTXを有効にしてビルドされている場合にのみ利用できます。新しいコードではctx=NULL、ctxLen=0でwc_MlDsaKey_VerifyCtx()を使用してください。

    \return wc_MlDsaKey_VerifyCtx()を参照してください。

    \param [in,out] key 公開鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [in] sig 検証する署名バイト列。
    \param [in] sigLen sigのバイト単位の長さ。
    \param [in] msg 署名対象であったメッセージ。
    \param [in] msgLen msgのバイト単位の長さ。
    \param [out] res 署名が有効な場合は1、それ以外の場合は0が設定されます。

    \sa wc_MlDsaKey_VerifyCtx
    \sa wc_MlDsaKey_Sign
*/
int wc_MlDsaKey_Verify(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* msg, word32 msgLen, int* res);

/*!
    \ingroup ML_DSA

    \brief この鍵に設定されているパラメータセットにおける、エンコードされた秘密鍵のサイズをバイト単位で返します。wc_MlDsaKey_PrivSize()と同等で、APIの互換性のために提供されています。

    \return 成功した場合、エンコードされた秘密鍵のサイズ(バイト単位、正の値)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、またはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。

    \sa wc_MlDsaKey_PrivSize
    \sa wc_MlDsaKey_PubSize
    \sa wc_MlDsaKey_SigSize
*/
int wc_MlDsaKey_Size(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief この鍵に設定されているパラメータセットにおける、エンコードされた秘密鍵のサイズをバイト単位で返します。

    \return 成功した場合、エンコードされた秘密鍵のサイズ(正の値)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、またはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。

    \sa wc_MlDsaKey_PubSize
    \sa wc_MlDsaKey_GetPrivLen
*/
int wc_MlDsaKey_PrivSize(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief この鍵に設定されているパラメータセットにおける、エンコードされた公開鍵のサイズをバイト単位で返します。

    \return 成功した場合、エンコードされた公開鍵のサイズ(正の値)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、またはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。

    \sa wc_MlDsaKey_PrivSize
    \sa wc_MlDsaKey_GetPubLen
*/
int wc_MlDsaKey_PubSize(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief この鍵のパラメータセットで生成される署名のサイズをバイト単位で返します。

    \return 成功した場合、署名のサイズ(正の値)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、またはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。

    \sa wc_MlDsaKey_GetSigLen
    \sa wc_MlDsaKey_SignCtx
*/
int wc_MlDsaKey_SigSize(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief エンコードされた秘密鍵のサイズを*lenに書き込みます。wc_MlDsaKey_PrivSize()と同じ情報を、出力パラメータ形式で提供します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合、あるいはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [out] len 秘密鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_MlDsaKey_PrivSize
*/
int wc_MlDsaKey_GetPrivLen(wc_MlDsaKey* key, int* len);

/*!
    \ingroup ML_DSA

    \brief エンコードされた公開鍵のサイズを*lenに書き込みます。wc_MlDsaKey_PubSize()と同じ情報を、出力パラメータ形式で提供します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合、あるいはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [out] len 公開鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_MlDsaKey_PubSize
*/
int wc_MlDsaKey_GetPubLen(wc_MlDsaKey* key, int* len);

/*!
    \ingroup ML_DSA

    \brief 署名のサイズを*lenに書き込みます。wc_MlDsaKey_SigSize()と同じ情報を、出力パラメータ形式で提供します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合、あるいはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [out] len 署名のサイズ(バイト単位)を受け取ります。

    \sa wc_MlDsaKey_SigSize
*/
int wc_MlDsaKey_GetSigLen(wc_MlDsaKey* key, int* len);

/*!
    \ingroup ML_DSA

    \brief 秘密鍵から公開鍵を再計算し、保存されている公開鍵と比較することでML-DSA鍵を自己検査します。wolfSSLがWOLFSSL_MLDSA_CHECK_KEYを有効にしてビルドされている場合にのみ利用できます。

    \return 0 鍵が整合している場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。
    \return PUBLIC_KEY_E 再計算した公開鍵が一致しない場合に返されます。

    \param [in] key 公開鍵部分と秘密鍵部分の両方が設定されたwc_MlDsaKeyへのポインタ。
*/
int wc_MlDsaKey_CheckKey(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief 生のML-DSA公開鍵をインポートします。パラメータセットは事前に鍵に設定されている必要があります。inLenは、設定されているパラメータセットに対してwc_MlDsaKey_PubSize()が返すサイズと一致しなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはinがNULLの場合に返されます。
    \return BUFFER_E inLenが期待される公開鍵サイズと一致しない場合に返されます。

    \param [in,out] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [in] in 生の公開鍵バイト列。
    \param [in] inLen inのバイト単位の長さ。

    \sa wc_MlDsaKey_ExportPubRaw
    \sa wc_MlDsaKey_ImportPrivRaw
*/
int wc_MlDsaKey_ImportPubRaw(wc_MlDsaKey* key, const byte* in, word32 inLen);

/*!
    \ingroup ML_DSA

    \brief 生のML-DSA秘密鍵をインポートします。パラメータセットは事前に設定されている必要があります。privSzはwc_MlDsaKey_PrivSize()が返すサイズと一致しなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはprivがNULLの場合に返されます。
    \return BUFFER_E privSzが期待される秘密鍵サイズと一致しない場合に返されます。

    \param [in,out] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [in] priv 生の秘密鍵バイト列。
    \param [in] privSz privのバイト単位の長さ。

    \sa wc_MlDsaKey_ExportPrivRaw
    \sa wc_MlDsaKey_ImportKey
*/
int wc_MlDsaKey_ImportPrivRaw(wc_MlDsaKey* key, const byte* priv,
    word32 privSz);

/*!
    \ingroup ML_DSA

    \brief 生のML-DSA鍵ペア(秘密鍵部分と公開鍵部分をまとめて)をインポートします。パラメータセットは事前に設定されている必要があります。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E privSzまたはpubSzが期待されるサイズと一致しない場合に返されます。

    \param [in,out] key パラメータセットが設定されたwc_MlDsaKeyへのポインタ。
    \param [in] priv 生の秘密鍵バイト列。
    \param [in] privSz privの長さ。
    \param [in] pub 生の公開鍵バイト列。
    \param [in] pubSz pubの長さ。

    \sa wc_MlDsaKey_ExportKey
*/
int wc_MlDsaKey_ImportKey(wc_MlDsaKey* key, const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz);

/*!
    \ingroup ML_DSA

    \brief 生のML-DSA公開鍵をエクスポートします。呼び出し時、*outLenはoutのサイズを表します。成功時には書き込まれたバイト数に更新されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E *outLenが公開鍵のサイズより小さい場合に返されます。

    \param [in] key 公開鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] out 公開鍵を受け取るバッファ。
    \param [in,out] outLen 入力時: outのサイズ。出力時: 書き込まれたバイト数。

    \sa wc_MlDsaKey_ImportPubRaw
*/
int wc_MlDsaKey_ExportPubRaw(wc_MlDsaKey* key, byte* out, word32* outLen);

/*!
    \ingroup ML_DSA

    \brief 生のML-DSA秘密鍵をエクスポートします。呼び出し時、*outLenはoutのサイズを表します。成功時には書き込まれたバイト数に更新されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E *outLenが秘密鍵のサイズより小さい場合に返されます。

    \param [in] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] out 秘密鍵を受け取るバッファ。
    \param [in,out] outLen 入力時: outのサイズ。出力時: 書き込まれたバイト数。

    \sa wc_MlDsaKey_ImportPrivRaw
*/
int wc_MlDsaKey_ExportPrivRaw(wc_MlDsaKey* key, byte* out, word32* outLen);

/*!
    \ingroup ML_DSA

    \brief 生の公開鍵と秘密鍵の両方のML-DSA鍵要素を1回の呼び出しでエクスポートします。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E いずれかのバッファが小さすぎる場合に返されます。

    \param [in] key 両方の鍵要素を保持するwc_MlDsaKeyへのポインタ。
    \param [out] priv 秘密鍵を受け取るバッファ。
    \param [in,out] privSz 入力時: privのサイズ。出力時: 書き込まれたバイト数。
    \param [out] pub 公開鍵を受け取るバッファ。
    \param [in,out] pubSz 入力時: pubのサイズ。出力時: 書き込まれたバイト数。

    \sa wc_MlDsaKey_ImportKey
*/
int wc_MlDsaKey_ExportKey(wc_MlDsaKey* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz);

/*!
    \ingroup ML_DSA

    \brief DER/ASN.1でエンコードされたバッファ(PKCS#8 OneAsymmetricKey)からML-DSA秘密鍵を解析します。パラメータセットはエンコード内のアルゴリズム識別子から推定されるため、事前に設定する必要はありません。成功時、*inOutIdxは消費したバイト数分進められます。

    WOLFSSL_MLDSA_NO_ASN1が定義されていない場合にのみ利用できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return ASN_PARSE_E エンコードの形式が不正な場合に返されます。

    \param [in,out] key 初期化済みのwc_MlDsaKeyへのポインタ。
    \param [in] input DERエンコードされた秘密鍵バイト列。
    \param [in] inSz inputのバイト単位の長さ。
    \param [in,out] inOutIdx 入力時: デコードを開始するinput内のオフセット。出力時: 消費したバイトの直後のオフセット。

    \sa wc_MlDsaKey_PrivateKeyToDer
    \sa wc_MlDsaKey_PublicKeyDecode
*/
int wc_MlDsaKey_PrivateKeyDecode(wc_MlDsaKey* key, const byte* input,
    word32 inSz, word32* inOutIdx);

/*!
    \ingroup ML_DSA

    \brief DER/ASN.1でエンコードされたバッファ(SubjectPublicKeyInfo)からML-DSA公開鍵を解析します。パラメータセットはアルゴリズム識別子から推定されます。成功時、*inOutIdxは消費したバイト数分進められます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return ASN_PARSE_E エンコードの形式が不正な場合に返されます。

    \param [in,out] key 初期化済みのwc_MlDsaKeyへのポインタ。
    \param [in] input DERエンコードされたSPKIバイト列。
    \param [in] inSz inputのバイト単位の長さ。
    \param [in,out] inOutIdx 入力時: デコードを開始するinput内のオフセット。出力時: 消費したバイトの直後のオフセット。

    \sa wc_MlDsaKey_PublicKeyToDer
*/
int wc_MlDsaKey_PublicKeyDecode(wc_MlDsaKey* key, const byte* input,
    word32 inSz, word32* inOutIdx);

/*!
    \ingroup ML_DSA

    \brief ML-DSA公開鍵をDERにエンコードします。withAlgが0以外の場合、出力は完全なSubjectPublicKeyInfo(AlgorithmIdentifierを含む)になります。0の場合、出力は生の公開鍵バイト列になります。

    必要なバッファサイズを問い合わせるには、outputにNULLを渡してください。

    \return 成功した場合、エンコードされたDERのサイズ(バイト単位)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、またはパラメータセットが選択されていない場合に返されます。
    \return BUFFER_E outputがNULLでなく、inLenが必要なサイズより小さい場合に返されます。

    \param [in] key 公開鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] output DERエンコードを受け取るバッファ。サイズを問い合わせる場合はNULL。
    \param [in] inLen outputのサイズ(outputがNULLの場合は無視されます)。
    \param [in] withAlg SubjectPublicKeyInfoを出力する場合は0以外、生の公開鍵のみを出力する場合は0。

    \sa wc_MlDsaKey_PublicKeyDecode
    \sa wc_MlDsaKey_KeyToDer
*/
int wc_MlDsaKey_PublicKeyToDer(wc_MlDsaKey* key, byte* output,
    word32 inLen, int withAlg);

/*!
    \ingroup ML_DSA

    \brief ML-DSA鍵ペア(公開鍵+秘密鍵)をPKCS#8 OneAsymmetricKey構造としてDERにエンコードします。必要なバッファサイズを問い合わせるには、outputにNULLを渡してください。

    \return 成功した場合、エンコードされたDERのサイズ(バイト単位)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、またはパラメータセットが選択されていない場合に返されます。
    \return MISSING_KEY 秘密鍵が設定されていない場合に返されます。
    \return BUFFER_E outputがNULLでなく、inLenが小さすぎる場合に返されます。

    \param [in] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] output DERエンコードを受け取るバッファ。サイズを問い合わせる場合はNULL。
    \param [in] inLen outputのサイズ(outputがNULLの場合は無視されます)。

    \sa wc_MlDsaKey_PrivateKeyDecode
    \sa wc_MlDsaKey_PrivateKeyToDer
    \sa wc_MlDsaKey_PublicKeyToDer
*/
int wc_MlDsaKey_KeyToDer(wc_MlDsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup ML_DSA

    \brief ML-DSA秘密鍵をDERにエンコードします。FIPS 204では秘密鍵のエンコードに公開鍵の要素が含まれるため、この関数は現在wc_MlDsaKey_KeyToDer()のエイリアスであり、他のアルゴリズムとのAPIの一貫性のために維持されています。

    \return 成功した場合、エンコードされたDERのサイズ(バイト単位)を返します。
    \return wc_MlDsaKey_KeyToDer()から引き継がれたエラーコードが返されます。

    \param [in] key 秘密鍵を保持するwc_MlDsaKeyへのポインタ。
    \param [out] output DERエンコードを受け取るバッファ。サイズを問い合わせる場合はNULL。
    \param [in] inLen outputのサイズ(outputがNULLの場合は無視されます)。

    \sa wc_MlDsaKey_KeyToDer
    \sa wc_MlDsaKey_PrivateKeyDecode
*/
int wc_MlDsaKey_PrivateKeyToDer(wc_MlDsaKey* key, byte* output,
    word32 inLen);
