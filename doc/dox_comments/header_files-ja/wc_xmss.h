/*!
    \ingroup XMSS

    \brief XmssKeyオブジェクトを初期化します。他のXMSS/XMSS^MT操作を行う前に呼び出さなければなりません。使用が終わったらwc_XmssKey_Free()でリソースを解放してください。

    XMSS(eXtended Merkle Signature Scheme)とそのマルチツリー版であるXMSS^MT(RFC 8391、NIST SP 800-208)は、状態を持つ(STATEFUL)ハッシュベースの署名方式です。wc_XmssKey_Sign()を呼び出すたびに秘密鍵のワンタイムコンポーネントが消費され、ワンタイム鍵を再利用するとこの方式の安全性は完全に失われます。アプリケーションは、署名を行うたびに、次の署名までの間に秘密鍵の状態を永続化しなければなりません。wc_XmssKey_SetWriteCb()およびwc_XmssKey_SetReadCb()を参照してください。

    初期化後、鍵はWC_XMSS_STATE_INITED状態になります。鍵を生成または再読み込みする前に、wc_XmssKey_SetParamStr()でパラメータセットを名前で選択しなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key 初期化するXmssKeyへのポインタ。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId ハードウェア暗号コールバック用のデバイス識別子。ソフトウェアのみで処理する場合はINVALID_DEVIDを使用します。

    _Example_
    \code
    XmssKey key;
    int ret;

    ret = wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // 鍵の初期化エラー
    }
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    // ... 鍵を使用 ...
    wc_XmssKey_Free(&key);
    \endcode

    \sa wc_XmssKey_Free
    \sa wc_XmssKey_SetParamStr
    \sa wc_XmssKey_MakeKey
*/
int wc_XmssKey_Init(XmssKey* key, void* heap, int devId);

/*!
    \ingroup XMSS

    \brief デバイス側の鍵識別子を指定してXmssKeyを初期化します。wc_XmssKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるバイナリ形式のidも保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    idは鍵オブジェクトへコピーされます。呼び出し側はこの関数から戻った直後に自身のバッファを解放して構いません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、またはlenが0より大きいにもかかわらずidがNULLの場合に返されます。
    \return BUFFER_E lenが負の場合、またはXMSS_MAX_ID_LENより大きい場合に返されます。

    \param [in,out] key 初期化するXmssKeyへのポインタ。
    \param [in] id デバイス側の鍵識別子バイト列へのポインタ。
    \param [in] len idのバイト数。[0, XMSS_MAX_ID_LEN]の範囲内でなければなりません。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。
    \param [in] devId 暗号コールバック用のデバイス識別子。

    \sa wc_XmssKey_Init
    \sa wc_XmssKey_InitLabel
    \sa wc_XmssKey_Free
*/
int wc_XmssKey_InitId(XmssKey* key, const unsigned char* id, int len,
    void* heap, int devId);

/*!
    \ingroup XMSS

    \brief デバイス側の鍵ラベルを指定してXmssKeyを初期化します。wc_XmssKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるラベル文字列も保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlabelがNULLの場合に返されます。
    \return BUFFER_E labelが空の場合、またはXMSS_MAX_LABEL_LENより長い場合に返されます。

    \param [in,out] key 初期化するXmssKeyへのポインタ。
    \param [in] label NUL終端されたデバイス側の鍵ラベル。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。
    \param [in] devId 暗号コールバック用のデバイス識別子。

    \sa wc_XmssKey_Init
    \sa wc_XmssKey_InitId
*/
int wc_XmssKey_InitLabel(XmssKey* key, const char* label, void* heap,
    int devId);

/*!
    \ingroup XMSS

    \brief XMSSまたはXMSS^MTのパラメータセットをRFC 8391の名前で選択します。受け付けられる名前は"XMSS-<hash>_<height>_<n>"(単一ツリー)または"XMSSMT-<hash>_<total_height>/<layers>_<n>"(マルチツリー)の形式で、例えば"XMSS-SHA2_10_256"や"XMSSMT-SHA2_20/2_256"です。実際に受け付けられる名前の集合は、ビルド時に有効化されたハッシュファミリとツリーの高さによって決まります。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはstrがNULLの場合、または指定された名前のパラメータセットが未知であるかコンパイルに含まれていない場合に返されます。
    \return BAD_STATE_E keyがWC_XMSS_STATE_INITED状態でない場合に返されます。

    \param [in,out] key WC_XMSS_STATE_INITED状態のXmssKeyへのポインタ。
    \param [in] str パラメータセット名(NUL終端)。

    _Example_
    \code
    XmssKey key;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    \endcode

    \sa wc_XmssKey_GetParamStr
    \sa wc_XmssKey_MakeKey
*/
int wc_XmssKey_SetParamStr(XmssKey* key, const char* str);

/*!
    \ingroup XMSS

    \brief この鍵に現在設定されているパラメータセット名を取得します。返されるポインタは静的な文字列を指しているため、呼び出し側が解放してはなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはstrがNULLの場合、またはパラメータセットが選択されていない場合に返されます。

    \param [in] key パラメータセットが選択されたXmssKeyへのポインタ。
    \param [out] str 静的なパラメータ名文字列へのポインタを受け取ります。

    \sa wc_XmssKey_SetParamStr
*/
int wc_XmssKey_GetParamStr(const XmssKey* key, const char** str);

/*!
    \ingroup XMSS

    \brief 更新された秘密鍵の状態を永続化するためにwolfSSLが呼び出すコールバックを登録します。XMSS/XMSS^MTは状態を持つため、アプリケーションは、署名が成功するたびに、その署名が渡される前に秘密鍵を永続化しなければなりません。そうしなければ、クラッシュや再起動によってワンタイム鍵が再利用され、この方式が破られる可能性があります。

    コールバックはwc_XmssRcコードのいずれかを返します。WC_XMSS_RC_SAVED_TO_NV_MEMORYは永続的な書き込みが完了したことを示します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはwrite_cbがNULLの場合に返されます。

    \param [in,out] key XmssKeyへのポインタ。
    \param [in] write_cb 秘密鍵を永続化するために呼び出されるコールバック。

    \sa wc_XmssKey_SetReadCb
    \sa wc_XmssKey_SetContext
    \sa wc_XmssKey_Sign
*/
int wc_XmssKey_SetWriteCb(XmssKey* key, wc_xmss_write_private_key_cb write_cb);

/*!
    \ingroup XMSS

    \brief 永続化された秘密鍵の状態を読み込むためにwolfSSLが呼び出すコールバックを登録します。保存された鍵をメモリに復元して署名を継続するために、wc_XmssKey_Reload()から使用されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはread_cbがNULLの場合に返されます。

    \param [in,out] key XmssKeyへのポインタ。
    \param [in] read_cb 秘密鍵を読み込むために呼び出されるコールバック。

    \sa wc_XmssKey_SetWriteCb
    \sa wc_XmssKey_Reload
*/
int wc_XmssKey_SetReadCb(XmssKey* key, wc_xmss_read_private_key_cb read_cb);

/*!
    \ingroup XMSS

    \brief 秘密鍵の読み込みコールバックと書き込みコールバックの両方に渡される、不透明なコンテキストポインタを設定します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key XmssKeyへのポインタ。
    \param [in] context アプリケーションが定義するポインタ。NULLでも構いません。

    \sa wc_XmssKey_SetReadCb
    \sa wc_XmssKey_SetWriteCb
*/
int wc_XmssKey_SetContext(XmssKey* key, void* context);

/*!
    \ingroup XMSS

    \brief 新しいXMSS/XMSS^MT鍵ペアを生成します。事前にwc_XmssKey_SetParamStr()でパラメータセットが選択され、読み込みコールバックと書き込みコールバックが登録されていなければなりません。新しく生成された秘密鍵は、この関数が戻る前に書き込みコールバックを介して永続化されます。成功時、鍵はWC_XMSS_STATE_OK状態に遷移します。

    ツリーの高さが大きい場合、鍵生成には時間がかかることがあります。XMSS^MTのバリアントは複数の小さなツリーにコストを分散するため、同等の単一ツリーXMSSパラメータセットに比べて鍵生成が大幅に高速です。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return MEMORY_E メモリ確保に失敗した場合に返されます。

    \param [in,out] key コールバックが設定され、WC_XMSS_STATE_PARMSET状態にあるXmssKeyへのポインタ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    _Example_
    \code
    XmssKey key;
    WC_RNG rng;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_SetWriteCb(&key, my_write_cb);
    wc_XmssKey_SetReadCb(&key, my_read_cb);
    wc_XmssKey_SetContext(&key, &my_storage);
    wc_InitRng(&rng);

    if (wc_XmssKey_MakeKey(&key, &rng) != 0) {
        // 鍵の生成エラー
    }
    \endcode

    \sa wc_XmssKey_Sign
    \sa wc_XmssKey_Reload
*/
int wc_XmssKey_MakeKey(XmssKey* key, WC_RNG* rng);

/*!
    \ingroup XMSS

    \brief 登録された読み込みコールバックを使用して、以前生成したXMSS/XMSS^MT秘密鍵を永続ストレージから再読み込みし、さらにメッセージへ署名できる状態に鍵を復元します。成功時、鍵はWC_XMSS_STATE_OK状態になります。

    Reloadを呼び出す前に、鍵生成時に選択したものと同じパラメータセットをwc_XmssKey_SetParamStr()で再適用しなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return WC_XMSS_RC_* 読み込みコールバックが失敗した場合、対応するエラーが返されます。

    \param [in,out] key パラメータと読み込みコールバックが設定されたXmssKeyへのポインタ。

    \sa wc_XmssKey_MakeKey
    \sa wc_XmssKey_SetReadCb
*/
int wc_XmssKey_Reload(XmssKey* key);

/*!
    \ingroup XMSS

    \brief この鍵に設定されているパラメータセットにおける、エンコードされた秘密鍵のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key パラメータが設定されたXmssKeyへのポインタ。
    \param [out] len 秘密鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_XmssKey_GetPubLen
    \sa wc_XmssKey_GetSigLen
*/
int wc_XmssKey_GetPrivLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief この鍵に設定されているパラメータセットにおける、XMSS/XMSS^MT公開鍵のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key パラメータが設定されたXmssKeyへのポインタ。
    \param [out] len 公開鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_XmssKey_ExportPubRaw
*/
int wc_XmssKey_GetPubLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief この鍵に設定されているパラメータセットにおける、署名のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key パラメータが設定されたXmssKeyへのポインタ。
    \param [out] len 署名のサイズ(バイト単位)を受け取ります。

    \sa wc_XmssKey_Sign
*/
int wc_XmssKey_GetSigLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief keyが保持するXMSS/XMSS^MT秘密鍵でmsgに署名します。呼び出し時、*sigSzはsigバッファのサイズを表します。成功時には書き込まれたバイト数に更新されます。

    署名が成功するたびに、秘密鍵のワンタイムコンポーネントが1つ消費されます。更新された鍵の状態は、新しい署名が呼び出し側に返される前に、登録された書き込みコールバックを介して永続化されます。書き込みコールバックが失敗した場合、署名の呼び出しも失敗し、署名は返されません。使用可能なワンタイム鍵を使い切ると、鍵はWC_XMSS_STATE_NOSIGS状態に遷移し、以降の署名の試行は失敗します。この状態を事前に検出するにはwc_XmssKey_SigsLeft()を問い合わせてください。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E *sigSzが署名のサイズより小さい場合に返されます。
    \return すべてのワンタイム鍵が使用済みの場合、負のエラーが返されます。

    \param [in,out] key WC_XMSS_STATE_OK状態のXmssKeyへのポインタ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] msg 署名するメッセージ。
    \param [in] msgSz msgのバイト単位の長さ。

    \sa wc_XmssKey_Verify
    \sa wc_XmssKey_SigsLeft
    \sa wc_XmssKey_SetWriteCb
*/
int wc_XmssKey_Sign(XmssKey* key, byte* sig, word32* sigSz, const byte* msg,
    int msgSz);

/*!
    \ingroup XMSS

    \brief この鍵で残り何回のワンタイム署名が可能かを返します。この数が0になると、鍵はそれ以上署名できないため、使用を終了してください。

    \return 成功した場合、残りの署名可能回数(非負の値)を返します。
    \return 失敗した場合は負のエラーコードが返されます(例: keyがNULLの場合はBAD_FUNC_ARG)。

    \param [in,out] key WC_XMSS_STATE_OK状態のXmssKeyへのポインタ。

    \sa wc_XmssKey_Sign
*/
int wc_XmssKey_SigsLeft(XmssKey* key);

/*!
    \ingroup XMSS

    \brief XmssKeyが保持しているリソースを解放します。NULLポインタを渡しても安全です。この呼び出しの後、鍵はWC_XMSS_STATE_FREED状態になり、再利用する前に再初期化しなければなりません。

    \param [in,out] key 解放するXmssKeyへのポインタ。

    \sa wc_XmssKey_Init
*/
void wc_XmssKey_Free(XmssKey* key);

/*!
    \ingroup XMSS

    \brief keySrcの公開鍵部分をkeyDstにコピーします。コピー先の鍵は同じパラメータセットを継承し、検証に使用できます。秘密鍵の状態は持たないため、署名はできません。検証者に必要最小限のデータだけを渡す場合に有用です。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyDstまたはkeySrcがNULLの場合に返されます。

    \param [in,out] keyDst 初期化済みのコピー先XmssKeyへのポインタ。
    \param [in] keySrc 公開鍵を保持するXmssKeyへのポインタ。

    \sa wc_XmssKey_ExportPub_ex
    \sa wc_XmssKey_ExportPubRaw
*/
int wc_XmssKey_ExportPub(XmssKey* keyDst, const XmssKey* keySrc);

/*!
    \ingroup XMSS

    \brief wc_XmssKey_ExportPub()と同様ですが、コピー先の鍵は指定されたheapとdevIdで新規に初期化されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyDstまたはkeySrcがNULLの場合に返されます。

    \param [in,out] keyDst 内容を設定する対象のXmssKeyへのポインタ。
    \param [in] keySrc 公開鍵を保持するXmssKeyへのポインタ。
    \param [in] heap keyDst用のヒープヒント。
    \param [in] devId keyDst用のデバイス識別子。

    \sa wc_XmssKey_ExportPub
*/
int wc_XmssKey_ExportPub_ex(XmssKey* keyDst, const XmssKey* keySrc,
    void* heap, int devId);

/*!
    \ingroup XMSS

    \brief XMSS/XMSS^MT公開鍵を生のバイト列としてエクスポートします。呼び出し時、*outLenはoutのサイズを表します。成功時には書き込まれたバイト数に更新されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E *outLenが公開鍵のサイズより小さい場合に返されます。

    \param [in] key XmssKeyへのポインタ。
    \param [out] out 公開鍵を受け取るバッファ。
    \param [in,out] outLen 入力時: outのサイズ。出力時: 書き込まれたバイト数。

    \sa wc_XmssKey_ImportPubRaw
    \sa wc_XmssKey_GetPubLen
*/
int wc_XmssKey_ExportPubRaw(const XmssKey* key, byte* out, word32* outLen);

/*!
    \ingroup XMSS

    \brief 生のXMSS公開鍵をkeyにインポートします。鍵はWC_XMSS_STATE_INITED状態であり、かつパラメータセットが事前に選択されていなければなりません(生のエンコードにはパラメータセットが含まれないため、呼び出し側が先にwc_XmssKey_SetParamStr()で適用する必要があります)。成功時、鍵はWC_XMSS_STATE_VERIFYONLY状態に遷移します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E inLenが期待される公開鍵サイズと一致しない場合に返されます。

    \param [in,out] key パラメータセットが設定されたXmssKeyへのポインタ。
    \param [in] in 生の公開鍵バイト列。
    \param [in] inLen inのバイト単位の長さ。

    \sa wc_XmssKey_ImportPubRaw_ex
    \sa wc_XmssKey_ExportPubRaw
    \sa wc_XmssKey_Verify
*/
int wc_XmssKey_ImportPubRaw(XmssKey* key, const byte* in, word32 inLen);

/*!
    \ingroup XMSS

    \brief wc_XmssKey_ImportPubRaw()と同様ですが、エンコードされた鍵が単一ツリーのXMSSかマルチツリーのXMSS^MTかを明示的に指定します(XMSS^MTの場合は0以外、XMSSの場合は0を渡します)。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E inLenが期待される公開鍵サイズと一致しない場合に返されます。

    \param [in,out] key パラメータセットが設定されたXmssKeyへのポインタ。
    \param [in] in 生の公開鍵バイト列。
    \param [in] inLen inのバイト単位の長さ。
    \param [in] is_xmssmt 鍵がXMSS^MTの場合は0以外、通常のXMSSの場合は0。

    \sa wc_XmssKey_ImportPubRaw
*/
int wc_XmssKey_ImportPubRaw_ex(XmssKey* key, const byte* in, word32 inLen,
    int is_xmssmt);

/*!
    \ingroup XMSS

    \brief keyが保持する公開鍵を使用して、msgに対するXMSS/XMSS^MT署名を検証します。この関数は署名が有効な場合にのみ0を返します。それ以外の値は署名が拒否されたことを示します。

    \return 0 署名が有効な場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return SIG_VERIFY_E (または類似のコード)署名が無効または形式が不正な場合に返されます。

    \param [in,out] key 公開鍵を保持するXmssKeyへのポインタ。
    \param [in] sig 検証する署名バイト列。
    \param [in] sigSz sigのバイト単位の長さ。
    \param [in] msg 署名対象であったメッセージ。
    \param [in] msgSz msgのバイト単位の長さ。

    \sa wc_XmssKey_Sign
    \sa wc_XmssKey_ImportPubRaw
*/
int wc_XmssKey_Verify(XmssKey* key, const byte* sig, word32 sigSz,
    const byte* msg, int msgSz);
