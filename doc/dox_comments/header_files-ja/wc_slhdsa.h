/*!
    \ingroup SLH_DSA

    \brief 指定されたパラメータセットでSLH-DSA鍵オブジェクトを初期化します。他のSLH-DSA操作を行う前に呼び出さなければなりません。使用が終わったらwc_SlhDsaKey_Free()でリソースを解放してください。

    SLH-DSA(FIPS 205)は状態を持たないハッシュベースのデジタル署名アルゴリズムです。パラメータセットによって、ハッシュ関数(SHAKEまたはSHA2)、セキュリティレベル(128、192、256)、速度とサイズのトレードオフ(s = 署名が小さい、f = 署名が高速)が決まります。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、またはparamが無効な場合に返されます。

    \param [in,out] key 初期化するSlhDsaKeyへのポインタ。
    \param [in] param 使用するパラメータセット。次のいずれか: SLHDSA_SHAKE128S、SLHDSA_SHAKE128F、SLHDSA_SHAKE192S、SLHDSA_SHAKE192F、SLHDSA_SHAKE256S、SLHDSA_SHAKE256F、SLHDSA_SHA2_128S、SLHDSA_SHA2_128F、SLHDSA_SHA2_192S、SLHDSA_SHA2_192F、SLHDSA_SHA2_256S、SLHDSA_SHA2_256F。
    \param [in] heap 動的メモリ確保に使用するヒープヒントへのポインタ。NULLでも構いません。
    \param [in] devId ハードウェア暗号コールバック用のデバイス識別子。ソフトウェアのみで処理する場合はINVALID_DEVIDを使用します。

    _Example_
    \code
    SlhDsaKey key;
    int ret;

    ret = wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    if (ret != 0) {
        // 鍵の初期化エラー
    }
    // ... 鍵を使用 ...
    wc_SlhDsaKey_Free(&key);
    \endcode

    \sa wc_SlhDsaKey_Free
    \sa wc_SlhDsaKey_MakeKey
*/
int wc_SlhDsaKey_Init(SlhDsaKey* key, enum SlhDsaParam param,
    void* heap, int devId);

/*!
    \ingroup SLH_DSA

    \brief デバイス側の鍵識別子(id)を指定してSLH-DSA鍵を初期化します。wc_SlhDsaKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるバイナリ形式のidも保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    idは鍵オブジェクトへコピーされます。呼び出し側はこの関数から戻った直後に自身のバッファを解放して構いません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合、またはlenが0より大きいにもかかわらずidがNULLの場合に返されます。
    \return BUFFER_E lenが負の場合、またはSLHDSA_MAX_ID_LENより大きい場合に返されます。

    \param [in,out] key 初期化するSlhDsaKeyへのポインタ。
    \param [in] param 使用するパラメータセット(wc_SlhDsaKey_Initを参照)。
    \param [in] id デバイス側の鍵識別子バイト列へのポインタ。lenが0の場合はNULLでも構いません。
    \param [in] len idのバイト数。[0, SLHDSA_MAX_ID_LEN]の範囲内でなければなりません。
    \param [in] heap 動的メモリ確保に使用するヒープヒントへのポインタ。NULLでも構いません。
    \param [in] devId 暗号コールバック用のデバイス識別子。idが意味を持つためには、INVALID_DEVIDではなく登録済みのコールバックのdevIdを指定してください。

    _Example_
    \code
    SlhDsaKey key;
    unsigned char id[8] = { 0x01, 0x02, 0x03, 0x04,
                            0x05, 0x06, 0x07, 0x08 };
    int ret;

    ret = wc_SlhDsaKey_Init_id(&key, SLHDSA_SHAKE128F, id, sizeof(id),
        NULL, devId);
    if (ret != 0) {
        // idを指定した鍵の初期化エラー
    }
    // ... 鍵を使用。コールバックがid -> デバイス鍵を解決します ...
    wc_SlhDsaKey_Free(&key);
    \endcode

    \sa wc_SlhDsaKey_Init
    \sa wc_SlhDsaKey_Init_label
    \sa wc_SlhDsaKey_Free
*/
int wc_SlhDsaKey_Init_id(SlhDsaKey* key, enum SlhDsaParam param,
    const unsigned char* id, int len, void* heap, int devId);

/*!
    \ingroup SLH_DSA

    \brief デバイス側の鍵ラベルを指定してSLH-DSA鍵を初期化します。wc_SlhDsaKey_Init()と同等ですが、暗号コールバックがデバイス上の実際の鍵素材を特定するために使用できるラベル文字列も保存します。wolfSSLがWOLF_PRIVATE_KEY_IDを有効にしてビルドされている場合にのみ利用できます。

    ラベルの長さはXSTRLENで取得されるため、途中にNULバイトが含まれるとそこでラベルが終端します。key->labelに保存されるコピーはNUL終端されているとは保証されません(入力がちょうどSLHDSA_MAX_LABEL_LENバイトの場合、配列全体が使用されます)。呼び出し側が読み取ってよいのは最大でkey->labelLenバイトまでです。key->labelをC文字列APIに渡してはいけません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはlabelがNULLの場合に返されます。
    \return BUFFER_E labelが空の場合、またはSLHDSA_MAX_LABEL_LENより長い場合に返されます。

    \param [in,out] key 初期化するSlhDsaKeyへのポインタ。
    \param [in] param 使用するパラメータセット(wc_SlhDsaKey_Initを参照)。
    \param [in] label NUL終端されたデバイス側の鍵ラベル文字列。
    \param [in] heap 動的メモリ確保に使用するヒープヒントへのポインタ。NULLでも構いません。
    \param [in] devId 暗号コールバック用のデバイス識別子。labelが意味を持つためには、INVALID_DEVIDではなく登録済みのコールバックのdevIdを指定してください。

    _Example_
    \code
    SlhDsaKey key;
    int ret;

    ret = wc_SlhDsaKey_Init_label(&key, SLHDSA_SHAKE128F,
        "device-key-1", NULL, devId);
    if (ret != 0) {
        // labelを指定した鍵の初期化エラー
    }
    // ... 鍵を使用。コールバックがlabel -> デバイス鍵を解決します ...
    wc_SlhDsaKey_Free(&key);
    \endcode

    \sa wc_SlhDsaKey_Init
    \sa wc_SlhDsaKey_Init_id
    \sa wc_SlhDsaKey_Free
*/
int wc_SlhDsaKey_Init_label(SlhDsaKey* key, enum SlhDsaParam param,
    const char* label, void* heap, int devId);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSA鍵オブジェクトに関連付けられたリソースを解放します。

    \param [in,out] key 解放するSlhDsaKeyへのポインタ。NULLでも構いません。

    _Example_
    \code
    SlhDsaKey key;
    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    // ... 鍵を使用 ...
    wc_SlhDsaKey_Free(&key);
    \endcode

    \sa wc_SlhDsaKey_Init
*/
void wc_SlhDsaKey_Free(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief RNGを乱数源として使用し、新しいSLH-DSA鍵ペアを生成します。鍵は事前にwc_SlhDsaKey_Init()で初期化されていなければなりません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはrngがNULLの場合、あるいはkeyが初期化されていない場合に返されます。

    \param [in,out] key 初期化済みのSlhDsaKeyへのポインタ。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    _Example_
    \code
    SlhDsaKey key;
    WC_RNG rng;
    int ret;

    wc_InitRng(&rng);
    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_MakeKey(&key, &rng);
    if (ret != 0) {
        // 鍵の生成エラー
    }
    \endcode

    \sa wc_SlhDsaKey_Init
    \sa wc_SlhDsaKey_MakeKeyWithRandom
*/
int wc_SlhDsaKey_MakeKey(SlhDsaKey* key, WC_RNG* rng);

/*!
    \ingroup SLH_DSA

    \brief 呼び出し側が提供したシード素材からSLH-DSA鍵ペアを生成します。これは決定的な鍵生成インターフェースであり、同じシードを与えれば同じ鍵ペアが生成されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはいずれかのシードポインタがNULLの場合、あるいは長さがパラメータセットのn値と一致しない場合に返されます。

    \param [in,out] key 初期化済みのSlhDsaKeyへのポインタ。
    \param [in] sk_seed 秘密鍵のシード(nバイト)。
    \param [in] sk_seed_len sk_seedの長さ。
    \param [in] sk_prf 秘密鍵のPRFシード(nバイト)。
    \param [in] sk_prf_len sk_prfの長さ。
    \param [in] pk_seed 公開鍵のシード(nバイト)。
    \param [in] pk_seed_len pk_seedの長さ。

    _Example_
    \code
    SlhDsaKey key;
    byte sk_seed[16], sk_prf[16], pk_seed[16]; // 128ビットパラメータではn=16
    int ret;

    // シードに既知の値を設定します(例: NISTテストベクタから)
    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_MakeKeyWithRandom(&key,
        sk_seed, sizeof(sk_seed),
        sk_prf, sizeof(sk_prf),
        pk_seed, sizeof(pk_seed));
    \endcode

    \sa wc_SlhDsaKey_MakeKey
*/
int wc_SlhDsaKey_MakeKeyWithRandom(SlhDsaKey* key,
    const byte* sk_seed, word32 sk_seed_len,
    const byte* sk_prf, word32 sk_prf_len,
    const byte* pk_seed, word32 pk_seed_len);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSAの外部(pure)インターフェースを使用し、決定的な乱数でメッセージに署名します。これはopt_randをPK.seedに設定したFIPS 205のアルゴリズム22に相当します。メッセージMは署名前に内部でM' = 0x00 || len(ctx) || ctx || Mとしてラップされます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、msg、sig、sigSzのいずれかがNULLの場合に返されます。
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx ドメイン分離のためのコンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] msg 署名するメッセージへのポインタ。
    \param [in] msgSz メッセージの長さ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    int ret;

    // 鍵はwc_SlhDsaKey_MakeKey()で生成済み
    ret = wc_SlhDsaKey_SignDeterministic(&key, NULL, 0,
        msg, sizeof(msg), sig, &sigSz);
    \endcode

    \sa wc_SlhDsaKey_SignWithRandom
    \sa wc_SlhDsaKey_Sign
    \sa wc_SlhDsaKey_Verify
*/
int wc_SlhDsaKey_SignDeterministic(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSAの外部(pure)インターフェースを使用し、呼び出し側が提供した追加の乱数でメッセージに署名します。これはopt_rand値を明示的に指定したFIPS 205のアルゴリズム22に相当します。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、msg、sig、sigSz、addRndのいずれかがNULLの場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] msg 署名するメッセージへのポインタ。
    \param [in] msgSz メッセージの長さ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。
    \param [in] addRnd 追加の乱数(nバイト。nはパラメータセットのセキュリティパラメータ)。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    byte addRnd[16]; // 128ビットパラメータではn=16
    int ret;

    wc_RNG_GenerateBlock(&rng, addRnd, sizeof(addRnd));
    ret = wc_SlhDsaKey_SignWithRandom(&key, NULL, 0,
        msg, sizeof(msg), sig, &sigSz, addRnd);
    \endcode

    \sa wc_SlhDsaKey_SignDeterministic
    \sa wc_SlhDsaKey_Sign
*/
int wc_SlhDsaKey_SignWithRandom(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    const byte* addRnd);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSAの外部(pure)インターフェースを使用し、RNGが提供する乱数でメッセージに署名します。これはopt_randにWC_RNGを使用する汎用の署名関数です。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、msg、sig、sigSz、rngのいずれかがNULLの場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] msg 署名するメッセージへのポインタ。
    \param [in] msgSz メッセージの長さ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    _Example_
    \code
    SlhDsaKey key;
    WC_RNG rng;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    int ret;

    ret = wc_SlhDsaKey_Sign(&key, NULL, 0,
        msg, sizeof(msg), sig, &sigSz, &rng);
    \endcode

    \sa wc_SlhDsaKey_SignDeterministic
    \sa wc_SlhDsaKey_Verify
*/
int wc_SlhDsaKey_Sign(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    WC_RNG* rng);

/*!
    \ingroup SLH_DSA

    \brief 外部(pure)インターフェースを使用して、メッセージに対するSLH-DSA署名を検証します。これはFIPS 205のアルゴリズム24に相当します。メッセージは検証前に内部でM' = 0x00 || len(ctx) || ctx || Mとしてラップされます。

    \return 0 成功した場合(署名が有効)に返されます。
    \return BAD_FUNC_ARG key、msg、sigのいずれかがNULLの場合、またはctxがNULLでctxSzが0より大きい場合に返されます。
    \return BAD_LENGTH_E sigSzがパラメータセットの署名長と一致しない場合に返されます。
    \return MISSING_KEY 公開鍵が設定されていない場合に返されます。
    \return SIG_VERIFY_E 署名が無効な場合に返されます。

    \param [in] key 公開鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] msg 検証するメッセージへのポインタ。
    \param [in] msgSz メッセージの長さ。
    \param [in] sig 検証する署名へのポインタ。
    \param [in] sigSz 署名の長さ。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[...]; // 以前に生成した署名
    word32 sigSz;
    byte msg[] = "Hello World!";
    int ret;

    ret = wc_SlhDsaKey_Verify(&key, NULL, 0,
        msg, sizeof(msg), sig, sigSz);
    if (ret == 0) {
        // 署名は有効です
    }
    \endcode

    \sa wc_SlhDsaKey_Sign
    \sa wc_SlhDsaKey_SignDeterministic
*/
int wc_SlhDsaKey_Verify(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, const byte* sig,
    word32 sigSz);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSAの内部インターフェースを使用し、決定的な乱数で署名します。外部インターフェースと異なり、M'は呼び出し側が直接提供し、ラップ処理は行われません。これはopt_randをPK.seedに設定したFIPS 205のアルゴリズム19(slh_sign_internal)に相当します。

    ACVPのsignatureInterface=internalテストフレームワークやプロトコル層が既にM'を構築している場合に使用してください。HashSLH-DSAの場合、呼び出し側はM'を0x01 || ctxSz || ctx || OID(hashType) || PHMとして構築してここに渡します。ここでPHMはhashTypeによるアプリケーションメッセージのハッシュです。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、mprime、sig、sigSzのいずれかがNULLの場合に返されます。
    \return BAD_LENGTH_E sigSzがパラメータセットの署名長より小さい場合に返されます。
    \return MISSING_KEY 秘密鍵が設定されていない場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] mprime 事前に構築されたM'メッセージへのポインタ。
    \param [in] mprimeSz M'の長さ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte mprime[] = { ... }; // 事前に構築したM'
    int ret;

    ret = wc_SlhDsaKey_SignMsgDeterministic(&key,
        mprime, sizeof(mprime), sig, &sigSz);
    \endcode

    \sa wc_SlhDsaKey_SignMsgWithRandom
    \sa wc_SlhDsaKey_VerifyMsg
    \sa wc_SlhDsaKey_SignDeterministic
    \sa wc_SlhDsaKey_SignHashDeterministic
*/
int wc_SlhDsaKey_SignMsgDeterministic(SlhDsaKey* key,
    const byte* mprime, word32 mprimeSz, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSAの内部インターフェースを使用し、呼び出し側が提供した追加の乱数で署名します。M'は直接提供され、ラップ処理は行われません。これはopt_rand値を明示的に指定したFIPS 205のアルゴリズム19(slh_sign_internal)に相当します。HashSLH-DSAで使用するM'のレイアウトについてはwc_SlhDsaKey_SignMsgDeterministicを参照してください。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、mprime、sig、sigSz、addRndのいずれかがNULLの場合に返されます。
    \return BAD_LENGTH_E sigSzがパラメータセットの署名長より小さい場合に返されます。
    \return MISSING_KEY 秘密鍵が設定されていない場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] mprime 事前に構築されたM'メッセージへのポインタ。
    \param [in] mprimeSz M'の長さ。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。
    \param [in] addRnd 追加の乱数(nバイト)。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte mprime[] = { ... };
    byte addRnd[16];
    int ret;

    wc_RNG_GenerateBlock(&rng, addRnd, sizeof(addRnd));
    ret = wc_SlhDsaKey_SignMsgWithRandom(&key,
        mprime, sizeof(mprime), sig, &sigSz, addRnd);
    \endcode

    \sa wc_SlhDsaKey_SignMsgDeterministic
    \sa wc_SlhDsaKey_VerifyMsg
    \sa wc_SlhDsaKey_SignHashWithRandom
*/
int wc_SlhDsaKey_SignMsgWithRandom(SlhDsaKey* key,
    const byte* mprime, word32 mprimeSz, byte* sig, word32* sigSz,
    const byte* addRnd);

/*!
    \ingroup SLH_DSA

    \brief 内部インターフェースを使用してSLH-DSA署名を検証します。M'は直接提供され、ラップ処理は行われません。これはFIPS 205のアルゴリズム20(slh_verify_internal)に相当します。

    \return 0 成功した場合(署名が有効)に返されます。
    \return BAD_FUNC_ARG key、mprime、sigのいずれかがNULLの場合に返されます。
    \return BAD_LENGTH_E sigSzがパラメータセットの署名長と一致しない場合に返されます。
    \return MISSING_KEY 公開鍵が設定されていない場合に返されます。
    \return SIG_VERIFY_E 署名が無効な場合に返されます。

    \param [in] key 公開鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] mprime 事前に構築されたM'メッセージへのポインタ。
    \param [in] mprimeSz M'の長さ。
    \param [in] sig 検証する署名へのポインタ。
    \param [in] sigSz 署名の長さ。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[...]; // 以前に生成した署名
    word32 sigSz;
    byte mprime[] = { ... };
    int ret;

    ret = wc_SlhDsaKey_VerifyMsg(&key,
        mprime, sizeof(mprime), sig, sigSz);
    if (ret == 0) {
        // 署名は有効です
    }
    \endcode

    \sa wc_SlhDsaKey_SignMsgDeterministic
    \sa wc_SlhDsaKey_Verify
    \sa wc_SlhDsaKey_VerifyHash
*/
int wc_SlhDsaKey_VerifyMsg(SlhDsaKey* key, const byte* mprime,
    word32 mprimeSz, const byte* sig, word32 sigSz);

/*!
    \ingroup SLH_DSA

    \brief 呼び出し側が事前にハッシュしたメッセージダイジェストに対して、SLH-DSAの外部(HashSLH-DSA)インターフェースを使用し、決定的な乱数で署名します。事前ハッシュのドメイン分離子(0x01)を用いたFIPS 205のアルゴリズム23に従います。呼び出し側が先にhashTypeでアプリケーションメッセージをハッシュし、そのダイジェストをhashとして渡さなければなりません。この関数は入力をハッシュしません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、hash、sig、sigSzのいずれかがNULLの場合に返されます。
    \return BAD_LENGTH_E hashSzがhashTypeのダイジェストサイズと一致しない場合に返されます(FIPS 205セクション10.2.2に従い、SHAKE128では32、SHAKE256では64)。
    \return NOT_COMPILED_IN hashTypeがこのビルドでサポートされていない場合に返されます。
    \return MISSING_KEY 秘密鍵が設定されていない場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] hash 事前にハッシュしたメッセージダイジェストへのポインタ。hashSzはhashTypeのダイジェストサイズと一致しなければなりません。
    \param [in] hashSz ダイジェストのバイト単位の長さ。
    \param [in] hashType 事前ハッシュに使用したハッシュアルゴリズム(OIDを選択します)。サポート: WC_HASH_TYPE_SHA224、WC_HASH_TYPE_SHA256、WC_HASH_TYPE_SHA384、WC_HASH_TYPE_SHA512、WC_HASH_TYPE_SHA512_224、WC_HASH_TYPE_SHA512_256、WC_HASH_TYPE_SHAKE128、WC_HASH_TYPE_SHAKE256、WC_HASH_TYPE_SHA3_224、WC_HASH_TYPE_SHA3_256、WC_HASH_TYPE_SHA3_384、WC_HASH_TYPE_SHA3_512。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    byte digest[WC_SHA256_DIGEST_SIZE];
    int ret;

    wc_Sha256Hash(msg, sizeof(msg), digest);
    ret = wc_SlhDsaKey_SignHashDeterministic(&key, NULL, 0,
        digest, sizeof(digest), WC_HASH_TYPE_SHA256, sig, &sigSz);
    \endcode

    \sa wc_SlhDsaKey_SignHashWithRandom
    \sa wc_SlhDsaKey_SignHash
    \sa wc_SlhDsaKey_VerifyHash
    \sa wc_SlhDsaKey_SignMsgDeterministic
*/
int wc_SlhDsaKey_SignHashDeterministic(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* hash, word32 hashSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief 呼び出し側が事前にハッシュしたメッセージダイジェストに対して、SLH-DSAの外部(HashSLH-DSA)インターフェースを使用し、呼び出し側が提供した追加の乱数で署名します。呼び出し側が先にhashTypeでアプリケーションメッセージをハッシュし、そのダイジェストをhashとして渡さなければなりません。この関数は入力をハッシュしません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、hash、sig、sigSz、addRndのいずれかがNULLの場合に返されます。
    \return BAD_LENGTH_E hashSzがhashTypeのダイジェストサイズと一致しない場合に返されます(FIPS 205セクション10.2.2に従い、SHAKE128では32、SHAKE256では64)。
    \return NOT_COMPILED_IN hashTypeがこのビルドでサポートされていない場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] hash 事前にハッシュしたメッセージダイジェストへのポインタ。hashSzはhashTypeのダイジェストサイズと一致しなければなりません。
    \param [in] hashSz ダイジェストのバイト単位の長さ。
    \param [in] hashType 事前ハッシュに使用したハッシュアルゴリズム(OIDを選択します)。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。
    \param [in] addRnd 追加の乱数(nバイト)。

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_VerifyHash
    \sa wc_SlhDsaKey_SignMsgWithRandom
*/
int wc_SlhDsaKey_SignHashWithRandom(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* hash, word32 hashSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz, const byte* addRnd);

/*!
    \ingroup SLH_DSA

    \brief 呼び出し側が事前にハッシュしたメッセージダイジェストに対して、SLH-DSAの外部(HashSLH-DSA)インターフェースを使用し、RNGが提供する乱数で署名します。呼び出し側が先にhashTypeでアプリケーションメッセージをハッシュし、そのダイジェストをhashとして渡さなければなりません。この関数は入力をハッシュしません。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、hash、sig、sigSz、rngのいずれかがNULLの場合に返されます。
    \return BAD_LENGTH_E hashSzがhashTypeのダイジェストサイズと一致しない場合に返されます(FIPS 205セクション10.2.2に従い、SHAKE128では32、SHAKE256では64)。
    \return NOT_COMPILED_IN hashTypeがこのビルドでサポートされていない場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] hash 事前にハッシュしたメッセージダイジェストへのポインタ。hashSzはhashTypeのダイジェストサイズと一致しなければなりません。
    \param [in] hashSz ダイジェストのバイト単位の長さ。
    \param [in] hashType 事前ハッシュに使用したハッシュアルゴリズム(OIDを選択します)。
    \param [out] sig 署名を受け取るバッファ。
    \param [in,out] sigSz 入力時はsigバッファのサイズ。出力時は実際の署名長。
    \param [in] rng 初期化済みのWC_RNGへのポインタ。

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_VerifyHash
    \sa wc_SlhDsaKey_SignMsgDeterministic
*/
int wc_SlhDsaKey_SignHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* hash, word32 hashSz, enum wc_HashType hashType,
    byte* sig, word32* sigSz, WC_RNG* rng);

/*!
    \ingroup SLH_DSA

    \brief 外部のHashSLH-DSAインターフェース(FIPS 205のアルゴリズム25)を使用してSLH-DSA署名を検証します。呼び出し側が先にhashTypeでアプリケーションメッセージをハッシュし、そのダイジェストをhashとして渡さなければなりません。この関数は入力をハッシュしません。

    \return 0 成功した場合(署名が有効)に返されます。
    \return BAD_FUNC_ARG key、hash、sigのいずれかがNULLの場合に返されます。
    \return BAD_LENGTH_E sigSzがパラメータセットと一致しない場合、またはhashSzがhashTypeのダイジェストサイズと一致しない場合に返されます(FIPS 205セクション10.2.2に従い、SHAKE128では32、SHAKE256では64)。
    \return NOT_COMPILED_IN hashTypeがこのビルドでサポートされていない場合に返されます。
    \return MISSING_KEY 公開鍵が設定されていない場合に返されます。
    \return SIG_VERIFY_E 署名が無効な場合に返されます。

    \param [in] key 公開鍵を保持するSlhDsaKeyへのポインタ。
    \param [in] ctx コンテキスト文字列。ctxSzが0の場合はNULLでも構いません。
    \param [in] ctxSz コンテキスト文字列の長さ(0〜255)。
    \param [in] hash 事前にハッシュしたメッセージダイジェストへのポインタ。hashSzはhashTypeのダイジェストサイズと一致しなければなりません。
    \param [in] hashSz ダイジェストのバイト単位の長さ。
    \param [in] hashType 事前ハッシュに使用したハッシュアルゴリズム(OIDを選択します)。署名時に使用したハッシュと一致しなければなりません。
    \param [in] sig 検証する署名へのポインタ。
    \param [in] sigSz 署名の長さ。

    _Example_
    \code
    SlhDsaKey key;
    byte sig[...];
    word32 sigSz;
    byte msg[] = "Hello World!";
    byte digest[WC_SHA256_DIGEST_SIZE];
    int ret;

    wc_Sha256Hash(msg, sizeof(msg), digest);
    ret = wc_SlhDsaKey_VerifyHash(&key, NULL, 0,
        digest, sizeof(digest), WC_HASH_TYPE_SHA256, sig, sigSz);
    if (ret == 0) {
        // 署名は有効です
    }
    \endcode

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_Verify
    \sa wc_SlhDsaKey_VerifyMsg
*/
int wc_SlhDsaKey_VerifyHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* hash, word32 hashSz, enum wc_HashType hashType,
    const byte* sig, word32 sigSz);

/*!
    \ingroup SLH_DSA

    \brief 生のバイトバッファからSLH-DSA秘密鍵をインポートします。バッファには秘密鍵全体(4*nバイト: SK.seed || SK.prf || PK.seed || PK.root)が含まれていなければなりません。インポート後、その鍵は署名に使用できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはinがNULLの場合、あるいはinLenがパラメータセットで期待される秘密鍵サイズと一致しない場合に返されます。

    \param [in,out] key 初期化済みのSlhDsaKeyへのポインタ。
    \param [in] in 生の秘密鍵バイト列を含むバッファ。
    \param [in] inLen 入力バッファの長さ。

    _Example_
    \code
    SlhDsaKey key;
    byte privKey[...]; // 4*nバイト
    int ret;

    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_ImportPrivate(&key, privKey, sizeof(privKey));
    \endcode

    \sa wc_SlhDsaKey_ExportPrivate
    \sa wc_SlhDsaKey_ImportPublic
*/
int wc_SlhDsaKey_ImportPrivate(SlhDsaKey* key, const byte* in,
    word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief 生のバイトバッファからSLH-DSA公開鍵をインポートします。バッファにはPK.seed || PK.root(2*nバイト)が含まれていなければなりません。インポート後、その鍵は検証に使用できます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはinがNULLの場合、あるいはinLenが期待される公開鍵サイズと一致しない場合に返されます。

    \param [in,out] key 初期化済みのSlhDsaKeyへのポインタ。
    \param [in] in 生の公開鍵バイト列を含むバッファ。
    \param [in] inLen 入力バッファの長さ。

    _Example_
    \code
    SlhDsaKey key;
    byte pubKey[...]; // 2*nバイト
    int ret;

    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_ImportPublic(&key, pubKey, sizeof(pubKey));
    \endcode

    \sa wc_SlhDsaKey_ExportPublic
    \sa wc_SlhDsaKey_ImportPrivate
*/
int wc_SlhDsaKey_ImportPublic(SlhDsaKey* key, const byte* in,
    word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSA鍵の整合性を検査します。秘密鍵と公開鍵の両方の要素を持つ鍵に対して、公開鍵が秘密鍵と一致することを検証します。

    \return 0 成功した場合(鍵が有効)に返されます。
    \return BAD_FUNC_ARG keyがNULLの場合に返されます。

    \param [in] key 検査するSlhDsaKeyへのポインタ。

    \sa wc_SlhDsaKey_MakeKey
    \sa wc_SlhDsaKey_ImportPrivate
*/
int wc_SlhDsaKey_CheckKey(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSA鍵オブジェクトから秘密鍵を生のバイトバッファ(4*nバイト)にエクスポートします。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、out、outLenのいずれかがNULLの場合に返されます。
    \return MISSING_KEY 秘密鍵が設定されていない場合に返されます。
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます。

    \param [in] key 秘密鍵を保持するSlhDsaKeyへのポインタ。
    \param [out] out 生の秘密鍵バイト列を受け取るバッファ。
    \param [in,out] outLen 入力時はoutバッファのサイズ。出力時は書き込まれたバイト数。

    _Example_
    \code
    SlhDsaKey key;
    byte privKey[4 * 32]; // 256ビットパラメータでは4*n
    word32 privKeySz = sizeof(privKey);
    int ret;

    ret = wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeySz);
    \endcode

    \sa wc_SlhDsaKey_ImportPrivate
    \sa wc_SlhDsaKey_ExportPublic
*/
int wc_SlhDsaKey_ExportPrivate(SlhDsaKey* key, byte* out,
    word32* outLen);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSA鍵オブジェクトから公開鍵を生のバイトバッファ(2*nバイト: PK.seed || PK.root)にエクスポートします。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG key、out、outLenのいずれかがNULLの場合に返されます。
    \return MISSING_KEY 公開鍵が設定されていない場合に返されます。
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます。

    \param [in] key 公開鍵を保持するSlhDsaKeyへのポインタ。
    \param [out] out 生の公開鍵バイト列を受け取るバッファ。
    \param [in,out] outLen 入力時はoutバッファのサイズ。出力時は書き込まれたバイト数。

    _Example_
    \code
    SlhDsaKey key;
    byte pubKey[2 * 32];
    word32 pubKeySz = sizeof(pubKey);
    int ret;

    ret = wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeySz);
    \endcode

    \sa wc_SlhDsaKey_ImportPublic
    \sa wc_SlhDsaKey_ExportPrivate
*/
int wc_SlhDsaKey_ExportPublic(SlhDsaKey* key, byte* out,
    word32* outLen);

/*!
    \ingroup SLH_DSA

    \brief この鍵のパラメータセットにおける秘密鍵のサイズをバイト単位で返します。

    \return 成功した場合、秘密鍵のサイズ(4*nバイト)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、または初期化されていない場合に返されます。

    \param [in] key 初期化済みのSlhDsaKeyへのポインタ。

    \sa wc_SlhDsaKey_PublicSize
    \sa wc_SlhDsaKey_SigSize
    \sa wc_SlhDsaKey_PrivateSizeFromParam
*/
int wc_SlhDsaKey_PrivateSize(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief この鍵のパラメータセットにおける公開鍵のサイズをバイト単位で返します。

    \return 成功した場合、公開鍵のサイズ(2*nバイト)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、または初期化されていない場合に返されます。

    \param [in] key 初期化済みのSlhDsaKeyへのポインタ。

    \sa wc_SlhDsaKey_PrivateSize
    \sa wc_SlhDsaKey_SigSize
    \sa wc_SlhDsaKey_PublicSizeFromParam
*/
int wc_SlhDsaKey_PublicSize(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief この鍵のパラメータセットにおける署名のサイズをバイト単位で返します。

    \return 成功した場合、署名のサイズ(バイト単位)を返します。
    \return BAD_FUNC_ARG keyがNULLの場合、または初期化されていない場合に返されます。

    \param [in] key 初期化済みのSlhDsaKeyへのポインタ。

    \sa wc_SlhDsaKey_PrivateSize
    \sa wc_SlhDsaKey_PublicSize
    \sa wc_SlhDsaKey_SigSizeFromParam
*/
int wc_SlhDsaKey_SigSize(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief 初期化済みの鍵オブジェクトを必要とせずに、指定されたパラメータセットにおける秘密鍵のサイズをバイト単位で返します。

    \return 成功した場合、秘密鍵のサイズ(4*nバイト)を返します。
    \return BAD_FUNC_ARG paramが無効な場合に返されます。

    \param [in] param SLH-DSAのパラメータセット。

    \sa wc_SlhDsaKey_PrivateSize
*/
int wc_SlhDsaKey_PrivateSizeFromParam(enum SlhDsaParam param);

/*!
    \ingroup SLH_DSA

    \brief 初期化済みの鍵オブジェクトを必要とせずに、指定されたパラメータセットにおける公開鍵のサイズをバイト単位で返します。

    \return 成功した場合、公開鍵のサイズ(2*nバイト)を返します。
    \return BAD_FUNC_ARG paramが無効な場合に返されます。

    \param [in] param SLH-DSAのパラメータセット。

    \sa wc_SlhDsaKey_PublicSize
*/
int wc_SlhDsaKey_PublicSizeFromParam(enum SlhDsaParam param);

/*!
    \ingroup SLH_DSA

    \brief 初期化済みの鍵オブジェクトを必要とせずに、指定されたパラメータセットにおける署名のサイズをバイト単位で返します。

    \return 成功した場合、署名のサイズ(バイト単位)を返します。
    \return BAD_FUNC_ARG paramが無効な場合に返されます。

    \param [in] param SLH-DSAのパラメータセット。

    \sa wc_SlhDsaKey_SigSize
*/
int wc_SlhDsaKey_SigSizeFromParam(enum SlhDsaParam param);

/*!
    \ingroup SLH_DSA

    \brief RFC 9909で定義されたPKCS#8 OneAsymmetricKey形式のDERエンコードされたSLH-DSA秘密鍵をデコードします。privateKey OCTET STRINGには、Ed25519/Ed448で使われるような入れ子のOCTET STRINGラッパーを介さず、生の連結SK.seed || SK.prf || PK.seed || PK.root(4*nバイト)が直接格納されます。SLH-DSAのパラメータセットはAlgorithmIdentifierのOIDから検出され、key->paramsがそれに合わせて更新されます。WOLFSSL_SLHDSA_VERIFY_ONLYが定義されていない場合にのみ利用できます。

    key->skへの書き込みが行われる前に検出された失敗(BAD_FUNC_ARG、ヘッダ/OIDの解析エラー、privateKeyの長さの誤り)では、鍵の状態は変更されません。wc_SlhDsaKey_ImportPrivateがkey->skを設定した後に検出された失敗(SHA-2の事前計算エラー、末尾フィールドの検証エラー)では、key->skはForceZeroで消去され、WC_SLHDSA_FLAG_PRIVATE/PUBLICフラグがクリアされます。これにより、ゼロクリアされたバイト列が有効な鍵としてフラグ付けされたまま残ることはありません。いずれのロールバックの場合も、key->paramsとinOutIdxは呼び出し前の値に復元されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG input、inOutIdx、keyのいずれかがNULLの場合、またはinSzが0の場合に返されます。
    \return ASN_PARSE_E DERをSLH-DSA秘密鍵として解析できない場合に返されます(入力の形式不正、鍵サイズの誤り、末尾フィールド違反)。
    \return NOT_COMPILED_IN OIDが、このライブラリに組み込まれていないSLH-DSAのバリアントを指している場合に返されます。

    \param [in] input DERエンコードされた鍵データ。
    \param [in,out] inOutIdx 入力時はinput内の開始オフセット。出力時は解析した鍵の直後まで進みます(失敗時は変更されません)。
    \param [in,out] key SLH-DSA鍵。パラメータセットはエンコードされたOIDから自動検出されます。
    \param [in] inSz inputの全体サイズ(バイト単位)。

    \sa wc_SlhDsaKey_KeyToDer
    \sa wc_SlhDsaKey_PublicKeyDecode
    \sa wc_SlhDsaKey_ImportPrivate
*/
int wc_SlhDsaKey_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    SlhDsaKey* key, word32 inSz);

/*!
    \ingroup SLH_DSA

    \brief SubjectPublicKeyInfo(SPKI)形式のDERエンコードされたSLH-DSA公開鍵をデコードします。SLH-DSAのパラメータセットはAlgorithmIdentifierのOIDから検出され、key->paramsがそれに応じて更新されます。

    高速パスとして、key->paramsが既に設定されている場合、この関数はまずinOutIdxからinSzまでのウィンドウ全体をwc_SlhDsaKey_ImportPublicに渡します。ImportPublicの長さチェックが判別要素となります。ちょうど2*nバイトのウィンドウは生の公開鍵(PK.seed || PK.root)として受け付けられ、全体が消費されます。それ以外の長さは拒否され、この関数はSPKIの解析へ進みます。SPKI入力は常にAlgorithmIdentifier/BIT STRINGのオーバーヘッドを十分に含むため、2*nという生の長さと衝突することはなく、問題なく解析へ進みます。呼び出し側がウィンドウを事前に2*nへ切り詰める必要はありません。

    書き込みが行われる前に検出された失敗(BAD_FUNC_ARG、形式不正なSPKI)では、鍵の状態は変更されません。ImportPublicがkey->skの公開鍵側を設定した後に検出された失敗(SHA-2の事前計算エラー)では、公開鍵側のsk[2*n .. 4*n]が消去され、フラグからWC_SLHDSA_FLAG_PUBLICがクリアされます。呼び出し側が事前に秘密鍵をインポートしていた場合に備え、秘密鍵側はそのまま残されます。key->paramsとinOutIdxは呼び出し前の値に復元されます。

    \return 0 成功した場合に返されます。
    \return BAD_FUNC_ARG input、inOutIdx、keyのいずれかがNULLの場合、またはinSzが0の場合に返されます。
    \return ASN_PARSE_E DERをSLH-DSA公開鍵として解析できない場合に返されます。
    \return NOT_COMPILED_IN OIDが、このライブラリに組み込まれていないSLH-DSAのバリアントを指している場合に返されます。

    \param [in] input DERエンコードされた鍵データ。key->paramsが既に設定されている場合は生の2*n公開鍵。
    \param [in,out] inOutIdx 入力時はinput内の開始オフセット。出力時は解析した鍵の直後まで進みます(失敗時は変更されません)。
    \param [in,out] key SLH-DSA鍵。パラメータセットはエンコードされたOIDから自動検出されます。ただし生の公開鍵を渡す高速パスでは、既に設定されているパラメータセットがそのまま使用されます。
    \param [in] inSz inputの全体サイズ(バイト単位)。

    \sa wc_SlhDsaKey_PublicKeyToDer
    \sa wc_SlhDsaKey_PrivateKeyDecode
    \sa wc_SlhDsaKey_ImportPublic
*/
int wc_SlhDsaKey_PublicKeyDecode(const byte* input, word32* inOutIdx,
    SlhDsaKey* key, word32 inSz);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSA秘密鍵を、RFC 9909で定義されたPKCS#8 OneAsymmetricKey形式のDERにエンコードします。privateKey OCTET STRINGには、Ed25519/Ed448で使われる入れ子のOCTET STRINGラッピングを介さず、生の4*nバイト(SK.seed || SK.prf || PK.seed || PK.root)が直接格納されます。

    WOLFSSL_SLHDSA_VERIFY_ONLYが定義されておらず、かつWC_ENABLE_ASYM_KEY_EXPORTが設定されている場合にのみ利用できます。

    \return 成功した場合、エンコードされたDERのサイズ(バイト単位)を返します。書き込みを行わずに必要なバッファサイズを問い合わせるには、outputにNULLを渡してください。
    \return BAD_FUNC_ARG keyまたはkey->paramsがNULLの場合に返されます。
    \return MISSING_KEY 秘密鍵が設定されていない場合に返されます。
    \return BUFFER_E outputがNULLでなく、inLenが必要なサイズより小さい場合に返されます。
    \return NOT_COMPILED_IN key->paramsが、パラメータセットが組み込まれていないSLH-DSAのバリアントを指している場合に返されます。

    \param [in] key 秘密鍵が設定されたSLH-DSA鍵。
    \param [out] output DERエンコードを受け取るバッファ。必要なサイズを問い合わせる場合はNULL。
    \param [in] inLen outputのバイト単位のサイズ(outputがNULLの場合は無視されます)。

    \sa wc_SlhDsaKey_PrivateKeyDecode
    \sa wc_SlhDsaKey_PrivateKeyToDer
    \sa wc_SlhDsaKey_PublicKeyToDer
*/
int wc_SlhDsaKey_KeyToDer(SlhDsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSA秘密鍵をDERにエンコードします。RFC 9909はSK.seed || SK.prf || PK.seed || PK.rootを単一のOCTET STRINGにまとめるため、SLH-DSAには秘密鍵のみの独立したエンコードが存在しません。この関数はwc_SlhDsaKey_KeyToDerの意図的なエイリアスであり、独立した秘密鍵形式を持つEd25519/Ed448とのAPIの一貫性のために維持されています。

    WOLFSSL_SLHDSA_VERIFY_ONLYが定義されておらず、かつWC_ENABLE_ASYM_KEY_EXPORTが設定されている場合にのみ利用できます。

    戻り値はwc_SlhDsaKey_KeyToDerからそのまま引き継がれます。

    \return 成功した場合、エンコードされたDERのサイズ(バイト単位)を返します。必要なバッファサイズを問い合わせるには、outputにNULLを渡してください。
    \return BAD_FUNC_ARG keyまたはkey->paramsがNULLの場合に返されます。
    \return MISSING_KEY 秘密鍵が設定されていない場合に返されます。
    \return BUFFER_E outputがNULLでなく、inLenが必要なサイズより小さい場合に返されます。
    \return NOT_COMPILED_IN key->paramsが、パラメータセットが組み込まれていないSLH-DSAのバリアントを指している場合に返されます。

    \param [in] key 秘密鍵が設定されたSLH-DSA鍵。
    \param [out] output DERエンコードを受け取るバッファ。必要なサイズを問い合わせる場合はNULL。
    \param [in] inLen outputのバイト単位のサイズ(outputがNULLの場合は無視されます)。

    \sa wc_SlhDsaKey_KeyToDer
    \sa wc_SlhDsaKey_PrivateKeyDecode
*/
int wc_SlhDsaKey_PrivateKeyToDer(SlhDsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief SLH-DSA公開鍵をDERにエンコードします。withAlgが0以外の場合、出力は完全なSubjectPublicKeyInfo構造(AlgorithmIdentifierとBIT STRING)になります。withAlgが0の場合、出力はSPKIのラッピングを伴わない生の公開鍵バイト列になります。

    WC_ENABLE_ASYM_KEY_EXPORTが設定されている場合にのみ利用できます。

    \return 成功した場合、エンコードされたDERのサイズ(バイト単位)を返します。必要なバッファサイズを問い合わせるには、outputにNULLを渡してください。
    \return BAD_FUNC_ARG keyまたはkey->paramsがNULLの場合に返されます。
    \return BUFFER_E outputがNULLでなく、inLenが必要なサイズより小さい場合に返されます。
    \return NOT_COMPILED_IN key->paramsが、パラメータセットが組み込まれていないSLH-DSAのバリアントを指している場合に返されます。

    \param [in] key 公開鍵が設定されたSLH-DSA鍵。
    \param [out] output DERエンコードを受け取るバッファ。必要なサイズを問い合わせる場合はNULL。
    \param [in] inLen outputのバイト単位のサイズ(outputがNULLの場合は無視されます)。
    \param [in] withAlg SubjectPublicKeyInfo(AlgorithmIdentifierを含む)を出力する場合は0以外、生の公開鍵のみを出力する場合は0。

    \sa wc_SlhDsaKey_PublicKeyDecode
    \sa wc_SlhDsaKey_KeyToDer
*/
int wc_SlhDsaKey_PublicKeyToDer(SlhDsaKey* key, byte* output, word32 inLen,
    int withAlg);
