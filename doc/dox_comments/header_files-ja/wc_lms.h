/*!
    \ingroup LMS

    \brief LmsKeyオブジェクトを初期化します。他のLMS/HSS操作を行う前に呼び出さなければなりません。使用が終わったらwc_LmsKey_Free()でリソースを解放してください。

    LMS(Leighton-Micali Signatures)とマルチツリー構成であるHSS(RFC 8554、NIST SP 800-208)は、状態を持つ(STATEFUL)ハッシュベースの署名方式です。wc_LmsKey_Sign()を呼び出すたびに秘密鍵のワンタイムコンポーネントが消費され、ワンタイム鍵を再利用するとこの方式の安全性は完全に失われます。アプリケーションは、署名を行うたびに、次の署名までの間に秘密鍵の状態を永続化しなければなりません。wc_LmsKey_SetWriteCb()およびwc_LmsKey_SetReadCb()を参照してください。

    初期化後、鍵はWC_LMS_STATE_INITED状態になります。鍵を生成または再読み込みする前に、wc_LmsKey_SetLmsParm()またはwc_LmsKey_SetParameters()でパラメータを設定しなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key 初期化するLmsKeyへのポインタ。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId ハードウェア暗号コールバック用のデバイス識別子。ソフトウェアのみで処理する場合はINVALID_DEVIDを使用します。

    _Example_
    \code
    LmsKey key;
    int ret;

    ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // 鍵の初期化エラー
    }
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    // ... 鍵を使用 ...
    wc_LmsKey_Free(&key);
    \endcode

    \sa wc_LmsKey_Free
    \sa wc_LmsKey_SetLmsParm
    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_MakeKey
*/
int wc_LmsKey_Init(LmsKey* key, void* heap, int devId);

/*!
    \ingroup LMS

    \brief デバイス側の鍵識別子を指定してLmsKeyを初期化します。wc_LmsKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるバイナリ形式のidも保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    idは鍵オブジェクトへコピーされます。呼び出し側はこの関数から戻った直後に自身のバッファを解放して構いません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、またはlenが0より大きいにもかかわらずidがNULLの場合に返されます。
    \return BUFFER_E lenが負の場合、またはLMS_MAX_ID_LENより大きい場合に返されます。

    \param [in,out] key 初期化するLmsKeyへのポインタ。
    \param [in] id デバイス側の鍵識別子バイト列へのポインタ。lenが0の場合はNULLでも構いません。
    \param [in] len idのバイト数。[0, LMS_MAX_ID_LEN]の範囲内でなければなりません。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。
    \param [in] devId 暗号コールバック用のデバイス識別子。

    \sa wc_LmsKey_Init
    \sa wc_LmsKey_InitLabel
    \sa wc_LmsKey_Free
*/
int wc_LmsKey_InitId(LmsKey* key, const unsigned char* id, int len,
    void* heap, int devId);

/*!
    \ingroup LMS

    \brief デバイス側の鍵ラベルを指定してLmsKeyを初期化します。wc_LmsKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるラベル文字列も保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlabelがNULLの場合に返されます。
    \return BUFFER_E labelが空の場合、またはLMS_MAX_LABEL_LENより長い場合に返されます。

    \param [in,out] key 初期化するLmsKeyへのポインタ。
    \param [in] label NUL終端されたデバイス側の鍵ラベル。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。
    \param [in] devId 暗号コールバック用のデバイス識別子。

    \sa wc_LmsKey_Init
    \sa wc_LmsKey_InitId
*/
int wc_LmsKey_InitLabel(LmsKey* key, const char* label, void* heap,
    int devId);

/*!
    \ingroup LMS

    \brief 定義済みのLMS/HSSパラメータセットを名前で選択します。列挙型wc_LmsParmは、ツリーの深さ(レベル数)、ツリーごとの高さ、Winternitzパラメータ、ハッシュファミリを1つの値にまとめています。特定のビルドで利用できる名前の一覧については、wc_LmsParmの定義を参照してください。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、またはlmsParmが認識できない場合、あるいはコンパイルに含まれていないパラメータセットを指している場合に返されます。
    \return BAD_STATE_E keyがWC_LMS_STATE_INITED状態でない場合に返されます。

    \param [in,out] key WC_LMS_STATE_INITED状態のLmsKeyへのポインタ。
    \param [in] lmsParm wc_LmsParm定数(例: WC_LMS_PARM_L2_H10_W8)。

    _Example_
    \code
    LmsKey key;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    \endcode

    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_GetParameters
    \sa wc_LmsKey_ParmToStr
*/
int wc_LmsKey_SetLmsParm(LmsKey* key, enum wc_LmsParm lmsParm);

/*!
    \ingroup LMS

    \brief LMS/HSSのパラメータを個別に設定します。デフォルトのSHA-256/256ハッシュが使用されます。ハッシュファミリをより細かく制御する場合はwc_LmsKey_SetParameters_ex()を使用してください。

    パラメータの組み合わせは、RFC 8554で許可されているセットのいずれかと一致しなければなりません。
      - levels:     1..8
      - height:     5、10、15、20(ビルドによっては25も)
      - winternitz: 1、2、4、8のいずれか

    1つの鍵から利用できる署名の最大数は2^(levels * height)です。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、または要求されたパラメータの組み合わせがこのビルドでサポートされていない場合に返されます。
    \return BAD_STATE_E keyがWC_LMS_STATE_INITED状態でない場合に返されます。

    \param [in,out] key WC_LMS_STATE_INITED状態のLmsKeyへのポインタ。
    \param [in] levels HSSチェーンにおけるマークルツリーのレベル数。
    \param [in] height 個々のマークルツリーの高さ。
    \param [in] winternitz Winternitzパラメータ(1、2、4、8のいずれか)。

    \sa wc_LmsKey_SetParameters_ex
    \sa wc_LmsKey_SetLmsParm
    \sa wc_LmsKey_GetParameters
*/
int wc_LmsKey_SetParameters(LmsKey* key, int levels, int height,
    int winternitz);

/*!
    \ingroup LMS

    \brief ハッシュファミリのセレクタを明示的に指定して、LMS/HSSのパラメータを個別に設定します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、または要求されたパラメータの組み合わせがこのビルドでサポートされていない場合に返されます。
    \return BAD_STATE_E keyがWC_LMS_STATE_INITED状態でない場合に返されます。

    \param [in,out] key WC_LMS_STATE_INITED状態のLmsKeyへのポインタ。
    \param [in] levels マークルツリーのレベル数。
    \param [in] height 各ツリーの高さ。
    \param [in] winternitz Winternitzパラメータ(1、2、4、8のいずれか)。
    \param [in] hash ビルドがサポートする範囲で、SHA-256/256、SHA-256/192、SHAKE256/256、SHAKE256/192を指定するハッシュファミリのセレクタ。

    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_GetParameters_ex
*/
int wc_LmsKey_SetParameters_ex(LmsKey* key, int levels, int height,
    int winternitz, int hash);

/*!
    \ingroup LMS

    \brief この鍵に以前設定されたLMS/HSSのパラメータを取得します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG いずれかのポインタがNULLの場合、またはパラメータが設定されていない場合に返されます。

    \param [in] key パラメータが設定されたLmsKeyへのポインタ。
    \param [out] levels ツリーのレベル数を受け取ります。
    \param [out] height ツリーごとの高さを受け取ります。
    \param [out] winternitz Winternitzパラメータを受け取ります。

    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_GetParameters_ex
*/
int wc_LmsKey_GetParameters(const LmsKey* key, int* levels, int* height,
    int* winternitz);

/*!
    \ingroup LMS

    \brief この鍵からLMS/HSSのパラメータとハッシュファミリのセレクタを取得します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG いずれかのポインタがNULLの場合、またはパラメータが設定されていない場合に返されます。

    \param [in] key パラメータが設定されたLmsKeyへのポインタ。
    \param [out] levels ツリーのレベル数を受け取ります。
    \param [out] height ツリーごとの高さを受け取ります。
    \param [out] winternitz Winternitzパラメータを受け取ります。
    \param [out] hash ハッシュファミリのセレクタを受け取ります。

    \sa wc_LmsKey_SetParameters_ex
*/
int wc_LmsKey_GetParameters_ex(const LmsKey* key, int* levels, int* height,
    int* winternitz, int* hash);

/*!
    \ingroup LMS

    \brief 更新された秘密鍵の状態を永続化するためにwolfSSLが呼び出すコールバックを登録します。LMS/HSSは状態を持つため、アプリケーションは、署名が成功するたびに、その署名が相手に渡される前に秘密鍵を永続化しなければなりません。そうしなければ、クラッシュや再起動によってワンタイム鍵が再利用され、この方式が破られる可能性があります。

    コールバックはエンコードされた秘密鍵のバイト列を受け取り、wc_LmsRcコードのいずれかを返します。WC_LMS_RC_SAVED_TO_NV_MEMORYは永続的な書き込みが完了したことを示します。それ以外の戻り値は失敗として扱われます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはwrite_cbがNULLの場合に返されます。

    \param [in,out] key LmsKeyへのポインタ。
    \param [in] write_cb 秘密鍵を永続化するために呼び出されるコールバック。

    \sa wc_LmsKey_SetReadCb
    \sa wc_LmsKey_SetContext
    \sa wc_LmsKey_Sign
*/
int wc_LmsKey_SetWriteCb(LmsKey* key, wc_lms_write_private_key_cb write_cb);

/*!
    \ingroup LMS

    \brief 永続化された秘密鍵の状態を読み込むためにwolfSSLが呼び出すコールバックを登録します。保存された鍵をメモリに復元して署名を継続するために、wc_LmsKey_Reload()から使用されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはread_cbがNULLの場合に返されます。

    \param [in,out] key LmsKeyへのポインタ。
    \param [in] read_cb 秘密鍵を読み込むために呼び出されるコールバック。

    \sa wc_LmsKey_SetWriteCb
    \sa wc_LmsKey_SetContext
    \sa wc_LmsKey_Reload
*/
int wc_LmsKey_SetReadCb(LmsKey* key, wc_lms_read_private_key_cb read_cb);

/*!
    \ingroup LMS

    \brief 秘密鍵の読み込みコールバックと書き込みコールバックの両方に渡される、不透明なコンテキストポインタを設定します。通常、ファイルハンドル、データベース接続、その他の永続化層の状態を保持するために使用されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key LmsKeyへのポインタ。
    \param [in] context アプリケーションが定義するポインタ。NULLでも構いません。

    \sa wc_LmsKey_SetReadCb
    \sa wc_LmsKey_SetWriteCb
*/
int wc_LmsKey_SetContext(LmsKey* key, void* context);

/*!
    \ingroup LMS

    \brief 新しいLMS/HSS鍵ペアを生成します。事前に(wc_LmsKey_SetLmsParm()またはwc_LmsKey_SetParameters()で)パラメータが設定され、読み込みコールバックと書き込みコールバックが登録されていなければなりません。新しく生成された秘密鍵は、この関数が戻る前に書き込みコールバックを介して永続化されます。成功時、鍵はWC_LMS_STATE_OK状態に遷移します。

    鍵生成の実行時間は最初のツリーの高さに応じて急激に増加します。3レベルでh=5の構成は、1レベルでh=15の構成よりも鍵生成がはるかに高速ですが、どちらも合計の署名可能回数は同じです。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return MEMORY_E メモリ確保に失敗した場合に返されます。

    \param [in,out] key コールバックが設定され、WC_LMS_STATE_PARMSET状態にあるLmsKeyへのポインタ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    _Example_
    \code
    LmsKey key;
    WC_RNG rng;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_SetWriteCb(&key, my_write_cb);
    wc_LmsKey_SetReadCb(&key, my_read_cb);
    wc_LmsKey_SetContext(&key, &my_storage);
    wc_InitRng(&rng);

    if (wc_LmsKey_MakeKey(&key, &rng) != 0) {
        // 鍵の生成エラー
    }
    \endcode

    \sa wc_LmsKey_Sign
    \sa wc_LmsKey_Reload
*/
int wc_LmsKey_MakeKey(LmsKey* key, WC_RNG* rng);

/*!
    \ingroup LMS

    \brief 登録された読み込みコールバックを使用して、以前生成したLMS/HSS秘密鍵を永続ストレージから再読み込みし、さらにメッセージへ署名できる状態に鍵を復元します。成功時、鍵はWC_LMS_STATE_OK状態になります。

    Reloadを呼び出す前に、鍵生成時に設定したものと同じパラメータをLmsKeyに再適用しなければなりません(永続化されるデータは秘密鍵のバイト列のみであり、パラメータセットはアプリケーションが管理するメタデータです)。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return WC_LMS_RC_* 読み込みコールバックが失敗した場合、対応するエラーが返されます。

    \param [in,out] key パラメータと読み込みコールバックが設定されたLmsKeyへのポインタ。

    \sa wc_LmsKey_MakeKey
    \sa wc_LmsKey_SetReadCb
*/
int wc_LmsKey_Reload(LmsKey* key);

/*!
    \ingroup LMS

    \brief この鍵に設定されているパラメータセットにおける、エンコードされた秘密鍵のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key パラメータが設定されたLmsKeyへのポインタ。
    \param [out] len 秘密鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_LmsKey_GetPubLen
    \sa wc_LmsKey_GetSigLen
*/
int wc_LmsKey_GetPrivLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief この鍵に設定されているパラメータセットにおける、LMS/HSS公開鍵のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key パラメータが設定されたLmsKeyへのポインタ。
    \param [out] len 公開鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_LmsKey_ExportPubRaw
    \sa wc_LmsKey_GetPrivLen
*/
int wc_LmsKey_GetPubLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief この鍵に設定されているパラメータセットにおける、LMS/HSS署名のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key パラメータが設定されたLmsKeyへのポインタ。
    \param [out] len 署名のサイズ(バイト単位)を受け取ります。

    \sa wc_LmsKey_Sign
*/
int wc_LmsKey_GetSigLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief keyが保持するLMS/HSS秘密鍵でmsgに署名します。呼び出し時、*sigSzはsigバッファのサイズを表します。成功時には書き込まれたバイト数に更新されます。

    署名が成功するたびに、秘密鍵のワンタイムコンポーネントが1つ消費されます。更新された鍵の状態は、新しい署名が呼び出し側に返される前に、登録された書き込みコールバックを介して永続化されます。書き込みコールバックが失敗した場合、署名の呼び出しも失敗し、署名は返されません。使用可能なワンタイム鍵を使い切ると、鍵はWC_LMS_STATE_NOSIGS状態に遷移し、以降の署名の試行はSIG_OTHER_E(または類似のコード)を返します。この状態を事前に検出するにはwc_LmsKey_SigsLeft()を問い合わせてください。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E *sigSzが署名のサイズより小さい場合に返されます。
    \return -1 (または類似のコード)すべてのワンタイム鍵が使用済みの場合に返されます。

    \param [in,out] key WC_LMS_STATE_OK状態のLmsKeyへのポインタ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時: sigのサイズ。出力時: 書き込まれたバイト数。
    \param [in] msg 署名するメッセージ。
    \param [in] msgSz msgのバイト単位の長さ。

    \sa wc_LmsKey_Verify
    \sa wc_LmsKey_SigsLeft
    \sa wc_LmsKey_SetWriteCb
*/
int wc_LmsKey_Sign(LmsKey* key, byte* sig, word32* sigSz, const byte* msg,
    int msgSz);

/*!
    \ingroup LMS

    \brief この鍵で残り何回のワンタイム署名が可能かを返します。この数が0になると、鍵はそれ以上署名できないため、使用を終了してください。

    \return 成功した場合、残りの署名可能回数(非負の値)を返します。
    \return 失敗した場合は負のエラーコードが返されます(例: keyがNULLの場合はBAD_FUNC_ARG)。

    \param [in,out] key WC_LMS_STATE_OK状態のLmsKeyへのポインタ。

    \sa wc_LmsKey_Sign
*/
int wc_LmsKey_SigsLeft(LmsKey* key);

/*!
    \ingroup LMS

    \brief LmsKeyが保持しているリソースを解放します。NULLポインタを渡しても安全です。この呼び出しの後、鍵はWC_LMS_STATE_FREED状態になり、再利用する前に再初期化しなければなりません。

    \param [in,out] key 解放するLmsKeyへのポインタ。

    \sa wc_LmsKey_Init
*/
void wc_LmsKey_Free(LmsKey* key);

/*!
    \ingroup LMS

    \brief keySrcの公開鍵部分をkeyDstにコピーします。コピー先の鍵は同じパラメータを継承し、検証に使用できます。秘密鍵の状態は持たないため、署名はできません。検証者に必要最小限のデータだけを渡す場合に有用です。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyDstまたはkeySrcがNULLの場合に返されます。

    \param [in,out] keyDst 初期化済みのコピー先LmsKeyへのポインタ。
    \param [in] keySrc 公開鍵を保持するLmsKeyへのポインタ。

    \sa wc_LmsKey_ExportPub_ex
    \sa wc_LmsKey_ExportPubRaw
*/
int wc_LmsKey_ExportPub(LmsKey* keyDst, const LmsKey* keySrc);

/*!
    \ingroup LMS

    \brief wc_LmsKey_ExportPub()と同様ですが、コピー先の鍵は指定されたheapとdevIdで新規に初期化されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyDstまたはkeySrcがNULLの場合に返されます。

    \param [in,out] keyDst 内容を設定する対象のLmsKeyへのポインタ。
    \param [in] keySrc 公開鍵を保持するLmsKeyへのポインタ。
    \param [in] heap keyDst用のヒープヒント。
    \param [in] devId keyDst用のデバイス識別子。

    \sa wc_LmsKey_ExportPub
*/
int wc_LmsKey_ExportPub_ex(LmsKey* keyDst, const LmsKey* keySrc, void* heap,
    int devId);

/*!
    \ingroup LMS

    \brief LMS/HSS公開鍵を生のバイト列としてエクスポートします。呼び出し時、*outLenはoutのサイズを表します。成功時には書き込まれたバイト数に更新されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E *outLenが公開鍵のサイズより小さい場合に返されます。

    \param [in] key LmsKeyへのポインタ。
    \param [out] out 公開鍵を受け取るバッファ。
    \param [in,out] outLen 入力時: outのサイズ。出力時: 書き込まれたバイト数。

    \sa wc_LmsKey_ImportPubRaw
    \sa wc_LmsKey_GetPubLen
*/
int wc_LmsKey_ExportPubRaw(const LmsKey* key, byte* out, word32* outLen);

/*!
    \ingroup LMS

    \brief 生のLMS/HSS公開鍵をkeyにインポートします。鍵はWC_LMS_STATE_INITED状態でなければなりません。パラメータ情報はエンコードされたヘッダから復元され、その後、鍵はWC_LMS_STATE_VERIFYONLY状態に遷移します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BUFFER_E inLenが小さすぎる場合に返されます。

    \param [in,out] key WC_LMS_STATE_INITED状態のLmsKeyへのポインタ。
    \param [in] in 生の公開鍵バイト列。
    \param [in] inLen inのバイト単位の長さ。

    \sa wc_LmsKey_ExportPubRaw
    \sa wc_LmsKey_Verify
*/
int wc_LmsKey_ImportPubRaw(LmsKey* key, const byte* in, word32 inLen);

/*!
    \ingroup LMS

    \brief keyが保持する公開鍵を使用して、msgに対するLMS/HSS署名を検証します。この関数は署名が有効な場合にのみ0を返します。それ以外の値は署名が拒否されたことを示します。

    \return 0 署名が有効な場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return SIG_VERIFY_E (または類似のコード)署名が無効または形式が不正な場合に返されます。

    \param [in,out] key 公開鍵が設定されたLmsKeyへのポインタ。
    \param [in] sig 検証する署名バイト列。
    \param [in] sigSz sigのバイト単位の長さ。
    \param [in] msg 署名対象であったメッセージ。
    \param [in] msgSz msgのバイト単位の長さ。

    \sa wc_LmsKey_Sign
    \sa wc_LmsKey_ImportPubRaw
*/
int wc_LmsKey_Verify(LmsKey* key, const byte* sig, word32 sigSz,
    const byte* msg, int msgSz);

/*!
    \ingroup LMS

    \brief LMSパラメータセットを説明する、静的でNUL終端された文字列を返します。ログ出力や診断に有用です。

    \return 成功した場合、静的な文字列へのポインタを返します。
    \return NULL lmsParmが認識できない場合に返されます。

    \param [in] lmsParm wc_LmsParm定数。

    \sa wc_LmsKey_SetLmsParm
*/
const char* wc_LmsKey_ParmToStr(enum wc_LmsParm lmsParm);

/*!
    \ingroup LMS

    \brief 秘密鍵に埋め込まれた16バイトのLMS鍵識別子(I)へのポインタと、その長さを返します。返されるポインタは内部の鍵メモリを参照しており、鍵が解放されるまでの間のみ有効です。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。

    \param [in,out] key 秘密鍵を保持するLmsKeyへのポインタ。
    \param [out] kid Iのバイト列へのポインタを受け取ります。
    \param [out] kidSz 長さ(16 / WC_LMS_I_LEN)を受け取ります。

    \sa wc_LmsKey_GetKidFromPrivRaw
*/
int wc_LmsKey_GetKid(LmsKey* key, const byte** kid, word32* kidSz);

/*!
    \ingroup LMS

    \brief LmsKeyオブジェクトを必要とせずに、生のエンコードされた秘密鍵バッファ内のLMS鍵識別子(I)へのポインタを返します。再読み込み時に、永続ストレージ内の対応する状態レコードを検索するために使用されます。

    \return 成功した場合、priv内のIのバイト列へのポインタを返します。
    \return NULL privがNULLの場合、またはprivSzが有効なヘッダを含むには小さすぎる場合に返されます。

    \param [in] priv エンコードされた秘密鍵バイト列。
    \param [in] privSz privのバイト単位の長さ。

    \sa wc_LmsKey_GetKid
*/
const byte* wc_LmsKey_GetKidFromPrivRaw(const byte* priv, word32 privSz);
