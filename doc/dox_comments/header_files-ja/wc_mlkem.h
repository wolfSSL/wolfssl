/*!
    \ingroup ML_KEM

    \brief 新しいMlKemKeyをヒープ上に確保して初期化します。返されたポインタはwc_MlKemKey_Delete()で解放しなければなりません。

    ML-KEM(FIPS 203)は耐量子の鍵カプセル化メカニズムです。typeパラメータでバリアントを選択します。WC_ML_KEM_512(NISTセキュリティレベル1)、WC_ML_KEM_768(レベル3)、WC_ML_KEM_1024(レベル5)のいずれかです。

    \return 成功した場合、新しく確保されたMlKemKeyへのポインタを返します。
    \return NULL メモリ確保に失敗した場合、またはtypeが無効な場合に返されます。

    \param [in] type ML-KEMのバリアント。WC_ML_KEM_512、WC_ML_KEM_768、WC_ML_KEM_1024のいずれか。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId ハードウェア暗号コールバック用のデバイス識別子。ソフトウェアのみで処理する場合はINVALID_DEVIDを使用します。

    _Example_
    \code
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_768, NULL,
        INVALID_DEVID);
    if (key == NULL) {
        // メモリ確保に失敗
    }
    // ... 鍵を使用 ...
    wc_MlKemKey_Delete(key, &key);
    \endcode

    \sa wc_MlKemKey_Delete
    \sa wc_MlKemKey_Init
*/
MlKemKey* wc_MlKemKey_New(int type, void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief wc_MlKemKey_New()が返したヒープ上のMlKemKeyをゼロクリアして解放します。成功時、key_pがNULLでない場合はkey_pを介して呼び出し側のポインタ変数にNULLが設定されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in,out] key 解放するMlKemKey。
    \param [in,out] key_p 呼び出し側のポインタ変数のアドレス(省略可)。NULLでない場合、成功時にNULLが設定されます。

    \sa wc_MlKemKey_New
*/
int wc_MlKemKey_Delete(MlKemKey* key, MlKemKey** key_p);

/*!
    \ingroup ML_KEM

    \brief 呼び出し側が用意したMlKemKeyオブジェクトを初期化します。typeパラメータはML-KEMのバリアントを選択し、WC_ML_KEM_512、WC_ML_KEM_768、WC_ML_KEM_1024のいずれかでなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、またはtypeが無効な場合に返されます。
    \return NOT_COMPILED_IN typeがビルド時に無効化されたバリアントを指している場合に返されます。

    \param [in,out] key 初期化するMlKemKeyへのポインタ。
    \param [in] type ML-KEMのバリアント。WC_ML_KEM_512、WC_ML_KEM_768、WC_ML_KEM_1024のいずれか。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。NULLでも構いません。
    \param [in] devId ハードウェア暗号コールバック用のデバイス識別子。

    _Example_
    \code
    MlKemKey key;
    int ret;

    ret = wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) {
        // 鍵の初期化エラー
    }
    // ... 鍵を使用 ...
    wc_MlKemKey_Free(&key);
    \endcode

    \sa wc_MlKemKey_Free
    \sa wc_MlKemKey_MakeKey
*/
int wc_MlKemKey_Init(MlKemKey* key, int type, void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief MlKemKeyが保持しているリソースを解放します。この呼び出しの後、オブジェクトを再度使用するにはwc_MlKemKey_Init()で再初期化しなければなりません。NULLポインタを渡しても安全です。

    \return 0 成功した場合に返されます。keyがNULLの場合も含みます。

    \param [in,out] key 解放するMlKemKeyへのポインタ。

    \sa wc_MlKemKey_Init
*/
int wc_MlKemKey_Free(MlKemKey* key);

/*!
    \ingroup ML_KEM

    \brief デバイス側の鍵識別子を指定してMlKemKeyを初期化します。wc_MlKemKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるバイナリ形式のidも保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    idは鍵オブジェクトへコピーされます。呼び出し側はこの関数から戻った直後に自身のバッファを解放して構いません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、lenが0でないにもかかわらずidがNULLの場合、またはtypeが無効な場合に返されます。
    \return BUFFER_E lenが負の場合、またはMLKEM_MAX_ID_LENを超える場合に返されます。

    \param [in,out] key 初期化するMlKemKeyへのポインタ。
    \param [in] type ML-KEMのバリアント識別子。
    \param [in] id デバイス側の鍵識別子バイト列へのポインタ。lenが0の場合はNULLでも構いません。
    \param [in] len idのバイト数。[0, MLKEM_MAX_ID_LEN]の範囲内でなければなりません。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。
    \param [in] devId 暗号コールバック用のデバイス識別子。

    \sa wc_MlKemKey_Init
    \sa wc_MlKemKey_Init_Label
    \sa wc_MlKemKey_Free
*/
int wc_MlKemKey_Init_Id(MlKemKey* key, int type, const unsigned char* id,
    int len, void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief デバイス側の鍵ラベルを指定してMlKemKeyを初期化します。wc_MlKemKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるラベル文字列も保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlabelがNULLの場合、またはtypeが無効な場合に返されます。

    \param [in,out] key 初期化するMlKemKeyへのポインタ。
    \param [in] type ML-KEMのバリアント識別子。
    \param [in] label NUL終端されたデバイス側の鍵ラベル。
    \param [in] heap 動的メモリ確保に使用するヒープヒント。
    \param [in] devId 暗号コールバック用のデバイス識別子。

    \sa wc_MlKemKey_Init
    \sa wc_MlKemKey_Init_Id
    \sa wc_MlKemKey_Free
*/
int wc_MlKemKey_Init_Label(MlKemKey* key, int type, const char* label,
    void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief 指定されたRNGを使用して新しいML-KEM鍵ペアを生成します。成功時には公開鍵と秘密鍵の両方の要素が設定されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはrngがNULLの場合に返されます。
    \return MEMORY_E メモリ確保に失敗した場合に返されます。

    \param [in,out] key 初期化済みのMlKemKeyへのポインタ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    _Example_
    \code
    MlKemKey key;
    WC_RNG rng;

    wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    wc_InitRng(&rng);

    if (wc_MlKemKey_MakeKey(&key, &rng) != 0) {
        // 鍵ペアの生成エラー
    }
    \endcode

    \sa wc_MlKemKey_MakeKeyWithRandom
    \sa wc_MlKemKey_Encapsulate
    \sa wc_MlKemKey_Decapsulate
*/
int wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng);

/*!
    \ingroup ML_KEM

    \brief 決定的な鍵生成を行います。RNGの代わりに、与えられた64バイトの乱数からML-KEM鍵ペアを生成します。既知解テストや、鍵の乱数を別の秘密から導出するアプリケーションで有用です。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはlenが64でない場合に返されます。

    \param [in,out] key 初期化済みのMlKemKeyへのポインタ。
    \param [in] rand 乱数バッファへのポインタ。
    \param [in] len randのバイト単位の長さ。64でなければなりません。

    \sa wc_MlKemKey_MakeKey
*/
int wc_MlKemKey_MakeKeyWithRandom(MlKemKey* key, const unsigned char* rand,
    int len);

/*!
    \ingroup ML_KEM

    \brief この鍵に設定されているバリアントの暗号文サイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key 初期化済みのMlKemKeyへのポインタ。
    \param [out] len 暗号文サイズ(バイト単位)を受け取ります。

    \sa wc_MlKemKey_SharedSecretSize
    \sa wc_MlKemKey_Encapsulate
*/
int wc_MlKemKey_CipherTextSize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief ML-KEMの共有秘密サイズをバイト単位で返します。この値はすべてのパラメータセットで同一(32バイト)ですが、wc_MlKemKey_CipherTextSize()との対称性のためにプログラムから問い合わせられるようになっています。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key 初期化済みのMlKemKeyへのポインタ。
    \param [out] len 共有秘密サイズ(バイト単位)を受け取ります。

    \sa wc_MlKemKey_CipherTextSize
*/
int wc_MlKemKey_SharedSecretSize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief keyが保持する公開鍵に対して、新しい共有秘密をカプセル化します。対応する秘密鍵の保持者がwc_MlKemKey_Decapsulate()に渡すことで同じ共有秘密を復元できる暗号文を生成します。

    ctバッファはwc_MlKemKey_CipherTextSize()バイト以上、ssバッファはwc_MlKemKey_SharedSecretSize()バイト以上でなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BAD_STATE_E 公開鍵が設定されていない場合に返されます。
    \return NOT_COMPILED_IN wolfSSLがWC_NO_RNGを指定してビルドされている場合に返されます。
    \return MEMORY_E カプセル化ルーチン内でメモリ確保に失敗した場合に返されます。

    \param [in,out] key 公開鍵を保持するMlKemKeyへのポインタ。
    \param [out] ct 暗号文を受け取るバッファ。
    \param [out] ss 32バイトの共有秘密を受け取るバッファ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    _Example_
    \code
    MlKemKey key;
    unsigned char ct[WC_ML_KEM_768_CIPHER_TEXT_SIZE];
    unsigned char ss[WC_ML_KEM_SS_SZ];

    // ... keyは受信者の公開鍵を保持している ...
    if (wc_MlKemKey_Encapsulate(&key, ct, ss, &rng) != 0) {
        // カプセル化中のエラー
    }
    // ctを対応する秘密鍵の保持者に送信します。
    \endcode

    \sa wc_MlKemKey_EncapsulateWithRandom
    \sa wc_MlKemKey_Decapsulate
*/
int wc_MlKemKey_Encapsulate(MlKemKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);

/*!
    \ingroup ML_KEM

    \brief wc_MlKemKey_Encapsulate()の決定的なバリアントです。RNGの出力を消費する代わりに、与えられた32バイトの乱数を使用します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはlenが32でない場合に返されます。

    \param [in,out] key 公開鍵を保持するMlKemKeyへのポインタ。
    \param [out] ct 暗号文を受け取るバッファ。
    \param [out] ss 32バイトの共有秘密を受け取るバッファ。
    \param [in] rand 乱数バッファ。
    \param [in] len randのバイト単位の長さ。32でなければなりません。

    \sa wc_MlKemKey_Encapsulate
*/
int wc_MlKemKey_EncapsulateWithRandom(MlKemKey* key, unsigned char* ct,
    unsigned char* ss, const unsigned char* rand, int len);

/*!
    \ingroup ML_KEM

    \brief keyが保持する秘密鍵を使用して暗号文のカプセル化を解除し、wc_MlKemKey_Encapsulate()が生成した共有秘密を復元します。ML-KEMのカプセル化解除は一定時間で実行され、不正な形式の暗号文に対する暗黙的拒否のチェックを含みます(攻撃者は実行時間からctの正当性を知ることはできません)。

    ssバッファはwc_MlKemKey_SharedSecretSize()バイト以上、ctはちょうどwc_MlKemKey_CipherTextSize()バイトでなければなりません。

    \return 0 成功した場合に返されます(共有秘密がssに書き込まれました)。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BAD_STATE_E 秘密鍵が設定されていない場合に返されます。
    \return BUFFER_E lenが、設定されているML-KEMバリアントで期待される暗号文サイズと一致しない場合に返されます。
    \return NOT_COMPILED_IN 鍵のML-KEMバリアントがビルド時に無効化されている場合に返されます。
    \return MEMORY_E メモリ確保に失敗した場合に返されます。

    \param [in,out] key 秘密鍵を保持するMlKemKeyへのポインタ。
    \param [out] ss 32バイトの共有秘密を受け取るバッファ。
    \param [in] ct カプセル化を解除する暗号文。
    \param [in] len ctのバイト単位の長さ。

    \sa wc_MlKemKey_Encapsulate
    \sa wc_MlKemKey_CipherTextSize
*/
int wc_MlKemKey_Decapsulate(MlKemKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);

/*!
    \ingroup ML_KEM

    \brief 生のML-KEM秘密鍵をデコードしてkeyに格納します。バリアントは事前に鍵に設定されている必要があり(通常はwc_MlKemKey_Init()またはwc_MlKemKey_New()で選択します)、lenはそのバリアントの秘密鍵サイズと一致しなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはlenが期待されるサイズと一致しない場合に返されます。

    \param [in,out] key 初期化済みのMlKemKeyへのポインタ。
    \param [in] in 生の秘密鍵バイト列。
    \param [in] len inのバイト単位の長さ。

    \sa wc_MlKemKey_EncodePrivateKey
    \sa wc_MlKemKey_PrivateKeySize
*/
int wc_MlKemKey_DecodePrivateKey(MlKemKey* key, const unsigned char* in,
    word32 len);

/*!
    \ingroup ML_KEM

    \brief 生のML-KEM公開鍵をデコードしてkeyに格納します。バリアントは事前に鍵に設定されている必要があり、lenはそのバリアントの公開鍵サイズと一致しなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはlenが期待されるサイズと一致しない場合に返されます。

    \param [in,out] key 初期化済みのMlKemKeyへのポインタ。
    \param [in] in 生の公開鍵バイト列。
    \param [in] len inのバイト単位の長さ。

    \sa wc_MlKemKey_EncodePublicKey
    \sa wc_MlKemKey_PublicKeySize
*/
int wc_MlKemKey_DecodePublicKey(MlKemKey* key, const unsigned char* in,
    word32 len);

/*!
    \ingroup ML_KEM

    \brief この鍵に設定されているバリアントの、エンコードされた秘密鍵のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key 初期化済みのMlKemKeyへのポインタ。
    \param [out] len 秘密鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_MlKemKey_PublicKeySize
*/
int wc_MlKemKey_PrivateKeySize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief この鍵に設定されているバリアントの、エンコードされた公開鍵のサイズをバイト単位で返します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlenがNULLの場合に返されます。

    \param [in] key 初期化済みのMlKemKeyへのポインタ。
    \param [out] len 公開鍵のサイズ(バイト単位)を受け取ります。

    \sa wc_MlKemKey_PrivateKeySize
*/
int wc_MlKemKey_PublicKeySize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief ML-KEM秘密鍵をエンコードしてoutに格納します。outバッファの長さはちょうどwc_MlKemKey_PrivateKeySize()バイトでなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BAD_STATE_E 鍵オブジェクトに秘密鍵と公開鍵のいずれかが設定されていない場合に返されます。
    \return BUFFER_E lenが、設定されているML-KEMバリアントでエンコードされた秘密鍵のサイズと完全に一致しない場合に返されます。
    \return NOT_COMPILED_IN 鍵のML-KEMバリアントがビルド時に無効化されている場合に返されます。

    \param [in] key 秘密鍵を保持するMlKemKeyへのポインタ。
    \param [out] out エンコードされた秘密鍵を受け取るバッファ。
    \param [in] len outのバイト単位の長さ。

    \sa wc_MlKemKey_DecodePrivateKey
    \sa wc_MlKemKey_PrivateKeySize
*/
int wc_MlKemKey_EncodePrivateKey(MlKemKey* key, unsigned char* out,
    word32 len);

/*!
    \ingroup ML_KEM

    \brief ML-KEM公開鍵をエンコードしてoutに格納します。outバッファの長さはちょうどwc_MlKemKey_PublicKeySize()バイトでなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合に返されます。
    \return BAD_STATE_E 公開鍵が設定されていない場合に返されます。
    \return BUFFER_E lenが、設定されているML-KEMバリアントでエンコードされた公開鍵のサイズと完全に一致しない場合に返されます。
    \return NOT_COMPILED_IN 鍵のML-KEMバリアントがビルド時に無効化されている場合に返されます。

    \param [in] key 公開鍵を保持するMlKemKeyへのポインタ。
    \param [out] out エンコードされた公開鍵を受け取るバッファ。
    \param [in] len outのバイト単位の長さ。

    \sa wc_MlKemKey_DecodePublicKey
    \sa wc_MlKemKey_PublicKeySize
*/
int wc_MlKemKey_EncodePublicKey(MlKemKey* key, unsigned char* out,
    word32 len);
