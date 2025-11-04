/*!
    \ingroup Random

    \brief グローバルWhitewood netRandomコンテキストを初期化します

    \return 0 成功
    \return BAD_FUNC_ARG configFileがnullまたはtimeoutが負の値の場合。
    \return RNG_FAILURE_E rngの初期化に失敗しました。

    \param configFile 設定ファイルへのパス
    \param hmac_cb HMACコールバックを作成するためのオプション。
    \param timeout タイムアウト期間。

    _Example_
    \code
    char* config = "path/to/config/example.conf";
    int time = // 十分なタイムアウト値;

    if (wc_InitNetRandom(config, NULL, time) != 0)
    {
        // エラーが発生しました
    }
    \endcode

    \sa wc_FreeNetRandom
*/
int  wc_InitNetRandom(const char* configFile, wnr_hmac_key hmac_cb, int timeout);

/*!
    \ingroup Random

    \brief グローバルWhitewood netRandomコンテキストを解放します。

    \return 0 成功
    \return BAD_MUTEX_E wnr_mutexのミューテックスロックエラー

    \param none 戻り値なし。

    _Example_
    \code
    int ret = wc_FreeNetRandom();
    if(ret != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_InitNetRandom
*/
int  wc_FreeNetRandom(void);

/*!
    \ingroup Random

    \brief rng用のシード(OSから)と鍵暗号を取得します。rng->drbg(決定論的乱数ビット生成器)が割り当てられます(wc_FreeRngで割り当て解除する必要があります)。これはブロッキング操作です。

    \return 0 成功時。
    \return MEMORY_E XMALLOCが失敗しました
    \return WINCRYPT_E wc_GenerateSeed: コンテキストの取得に失敗しました
    \return CRYPTGEN_E wc_GenerateSeed: ランダムの取得に失敗しました
    \return BAD_FUNC_ARG wc_RNG_GenerateBlock入力がnullまたはszがMAX_REQUEST_LENを超えています
    \return DRBG_CONT_FIPS_E wc_RNG_GenerateBlock: Hash_genがDRBG_CONT_FAILUREを返しました
    \return RNG_FAILURE_E wc_RNG_GenerateBlock: デフォルトエラー。rngのステータスが元々okでないか、DRBG_FAILEDに設定されています

    \param rng シードと鍵暗号で使用するために初期化される乱数生成器

    _Example_
    \code
    RNG  rng;
    int ret;

    #ifdef HAVE_CAVIUM
    ret = wc_InitRngCavium(&rng, CAVIUM_DEV_ID);
    if (ret != 0){
        printf("RNG Nitrox init for device: %d failed", CAVIUM_DEV_ID);
        return -1;
    }
    #endif
    ret = wc_InitRng(&rng);
    if (ret != 0){
        printf("RNG init failed");
        return -1;
    }
    \endcode

    \sa wc_InitRngCavium
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
int  wc_InitRng(WC_RNG*);

/*!
    \ingroup Random

    \brief 疑似乱数データのszバイトをoutputにコピーします。必要に応じてrngを再シードします(ブロッキング)。

    \return 0 成功時
    \return BAD_FUNC_ARG 入力がnullまたはszがMAX_REQUEST_LENを超えています
    \return DRBG_CONT_FIPS_E Hash_genがDRBG_CONT_FAILUREを返しました
    \return RNG_FAILURE_E デフォルトエラー。rngのステータスが元々okでないか、DRBG_FAILEDに設定されています

    \param rng wc_InitRngで初期化された乱数生成器
    \param output ブロックがコピーされるバッファ
    \param sz 出力のサイズ(バイト単位)

    _Example_
    \code
    RNG  rng;
    int  sz = 32;
    byte block[sz];

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //rngの初期化失敗!
    }

    ret = wc_RNG_GenerateBlock(&rng, block, sz);
    if (ret != 0) {
        return -1; //ブロック生成失敗!
    }
    \endcode

    \sa wc_InitRngCavium, wc_InitRng
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
int  wc_RNG_GenerateBlock(WC_RNG* rng, byte* b, word32 sz);

/*!
    \ingroup Random

    \brief 新しいWC_RNG構造体を作成します。


    \return WC_RNG 成功時の構造体
    \return NULL エラー時


    \param heap ヒープ識別子へのポインタ
    \param nonce nonceを含むバッファへのポインタ
    \param nonceSz nonceの長さ

    _Example_
    \code
    RNG  rng;
    byte nonce[] = { nonceを初期化 };
    word32 nonceSz = sizeof(nonce);

    wc_rng_new(&nonce, nonceSz, &heap);


    \endcode

    \sa wc_InitRng
    \sa wc_rng_free
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
WC_RNG* wc_rng_new(byte* nonce, word32 nonceSz, void* heap)

/*!
    \ingroup Random

    \brief 疑似乱数データの1バイトをbにコピーするためにwc_RNG_GenerateBlockを呼び出します。必要に応じてrngを再シードします。

    \return 0 成功時
    \return BAD_FUNC_ARG 入力がnullまたはszがMAX_REQUEST_LENを超えています
    \return DRBG_CONT_FIPS_E Hash_genがDRBG_CONT_FAILUREを返しました
    \return RNG_FAILURE_E デフォルトエラー。rngのステータスが元々okでないか、DRBG_FAILEDに設定されています

    \param rng: wc_InitRngで初期化された乱数生成器
    \param b ブロックがコピーされる1バイトのバッファ

    _Example_
    \code
    RNG  rng;
    int  sz = 32;
    byte b[1];

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //rngの初期化失敗!
    }

    ret = wc_RNG_GenerateByte(&rng, b);
    if (ret != 0) {
        return -1; //ブロック生成失敗!
    }
    \endcode

    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
int  wc_RNG_GenerateByte(WC_RNG* rng, byte* b);

/*!
    \ingroup Random

    \brief drgbを安全に解放するために、RNGが不要になったときに呼び出す必要があります。rng-drbgをゼロ化しXFREEします。

    \return 0 成功時
    \return BAD_FUNC_ARG rngまたはrng->drgbがnull
    \return RNG_FAILURE_E drbgの割り当て解除に失敗しました

    \param rng wc_InitRngで初期化された乱数生成器

    _Example_
    \code
    RNG  rng;
    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //rngの初期化失敗!
    }

    int ret = wc_FreeRng(&rng);
    if (ret != 0) {
        return -1; //rngの解放失敗!
    }
    \endcode

    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte,
    \sa wc_RNG_HealthTest
*/
int  wc_FreeRng(WC_RNG*);

/*!
    \ingroup Random

    \brief rngを安全に解放するために、RNGが不要になったときに呼び出す必要があります。


    \param rng wc_InitRngで初期化された乱数生成器

    _Example_
    \code
    RNG  rng;
    byte nonce[] = { nonceを初期化 };
    word32 nonceSz = sizeof(nonce);

    rng = wc_rng_new(&nonce, nonceSz, &heap);

    // rngを使用

    wc_rng_free(&rng);

    \endcode

    \sa wc_InitRng
    \sa wc_rng_new
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
WC_RNG* wc_rng_free(WC_RNG* rng);

/*!
    \ingroup Random

    \brief drbgの機能を作成してテストします。

    \return 0 成功時
    \return BAD_FUNC_ARG seedAとoutputはnullであってはなりません。reseedが設定されている場合、seedBはnullであってはなりません
    \return -1 テスト失敗

    \param int reseed: 設定されている場合、再シード機能をテストします
    \param seedA: drgbをインスタンス化するシード
    \param seedASz: seedAのサイズ(バイト単位)
    \param seedB: reseedが設定されている場合、drbgはseedBで再シードされます
    \param seedBSz: seedBのサイズ(バイト単位)
    \param output: seedrandomが設定されている場合はseedBでシードされたランダムデータに初期化され、それ以外の場合はseedAでシードされます
    \param outputSz: outputの長さ(バイト単位)

    _Example_
    \code
    byte output[SHA256_DIGEST_SIZE * 4];
    const byte test1EntropyB[] = ....; // reseed falseのテスト入力
    const byte test1Output[] = ....;   // テストベクター: reseed falseの期待出力
    ret = wc_RNG_HealthTest(0, test1Entropy, sizeof(test1Entropy), NULL, 0,
                        output, sizeof(output));
    if (ret != 0)
        return -1;//再シードなしのヘルステスト失敗

    if (XMEMCMP(test1Output, output, sizeof(output)) != 0)
        return -1; //テストベクターとの比較失敗: 予期しない出力

    const byte test2EntropyB[] = ....; // reseedのテスト入力
    const byte test2Output[] = ....;   // テストベクターreseedの期待出力
    ret = wc_RNG_HealthTest(1, test2EntropyA, sizeof(test2EntropyA),
                        test2EntropyB, sizeof(test2EntropyB),
                        output, sizeof(output));

    if (XMEMCMP(test2Output, output, sizeof(output)) != 0)
        return -1; //テストベクターとの比較失敗
    \endcode

    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
*/
int wc_RNG_HealthTest(int reseed, const byte* seedA, word32 seedASz,
        const byte* seedB, word32 seedBSz,
        byte* output, word32 outputSz);