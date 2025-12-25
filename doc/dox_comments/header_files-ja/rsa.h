/*!
    \ingroup RSA

    \brief この関数は、提供されたRsaKey構造体を初期化します。また、ユーザー定義のメモリオーバーライド（XMALLOC、XFREE、XREALLOCを参照）で使用するために、ヒープ識別子も受け取ります。

    WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return 0 暗号化と復号に使用するRSA構造体の初期化に成功した場合に返されます
    \return BAD_FUNC_ARGS RSAキーポインタがNULLと評価された場合に返されます

    \param key 初期化するRsaKey構造体へのポインタ
    \param heap メモリオーバーライドで使用するヒープ識別子へのポインタ。メモリ割り当てのカスタム処理を可能にします。このヒープは、このRSAオブジェクトで使用するメモリを割り当てる際にデフォルトで使用されます

    _Example_
    \code
    RsaKey enc;
    int ret;
    ret = wc_InitRsaKey(&enc, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    if ( ret != 0 ) {
    	// RSAキーの初期化エラー
    }
    \endcode

    \sa wc_FreeRsaKey
    \sa wc_RsaSetRNG
*/
int  wc_InitRsaKey(RsaKey* key, void* heap);

/*!
    \ingroup RSA

    \brief この関数は、提供されたRsaKey構造体を初期化します。idとlenは、デバイス上のキーを識別するために使用され、devIdはデバイスを識別します。また、ユーザー定義のメモリオーバーライド（XMALLOC、XFREE、XREALLOCを参照）で使用するために、ヒープ識別子も受け取ります。

    WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return 0 暗号化と復号に使用するRSA構造体の初期化に成功した場合に返されます
    \return BAD_FUNC_ARGS RSAキーポインタがNULLと評価された場合に返されます
    \return BUFFER_E lenが0未満またはRSA_MAX_ID_LENより大きい場合に返されます。

    \param key 初期化するRsaKey構造体へのポインタ
    \param id デバイス上のキーの識別子
    \param len 識別子の長さ（バイト単位）
    \param heap メモリオーバーライドで使用するヒープ識別子へのポインタ。メモリ割り当てのカスタム処理を可能にします。このヒープは、このRSAオブジェクトで使用するメモリを割り当てる際にデフォルトで使用されます
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定

    _Example_
    \code
    RsaKey enc;
    unsigned char* id = (unsigned char*)"RSA2048";
    int len = 7;
    int devId = 1;
    int ret;
    ret = wc_CryptoDev_RegisterDevice(devId, wc_Pkcs11_CryptoDevCb,
                                      &token);
    if ( ret != 0) {
        // コールバックとトークンをデバイスIDに関連付けるエラー
    }
    ret = wc_InitRsaKey_Id(&enc, id, len, NULL, devId); // ヒープヒントを使用しない
    if ( ret != 0 ) {
        // RSAキーの初期化エラー
    }
    \endcode

    \sa wc_InitRsaKey
    \sa wc_FreeRsaKey
    \sa wc_RsaSetRNG
*/
int  wc_InitRsaKey_Id(RsaKey* key, unsigned char* id, int len,
        void* heap, int devId);

/*!
    \ingroup RSA

    \brief この関数は、RNGをキーに関連付けます。WC_RSA_BLINDINGが有効になっている場合に必要です。

    \return 0 成功時に返されます
    \return BAD_FUNC_ARGS RSAキー、rngポインタがNULLと評価された場合に返されます

    \param key 関連付けるRsaKey構造体へのポインタ
    \param rng 関連付けるWC_RNG構造体へのポインタ

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    \endcode

    \sa wc_InitRsaKey
    \sa wc_RsaSetRNG
*/
int wc_RsaSetRNG(RsaKey* key, WC_RNG* rng);

/*!
    \ingroup RSA

    \brief この関数は、mp_clearを使用して提供されたRsaKey構造体を解放します。

    \return 0 キーの解放に成功した場合に返されます

    \param key 解放するRsaKey構造体へのポインタ

    _Example_
    \code
    RsaKey enc;
    wc_InitRsaKey(&enc, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    ... キーを設定し、暗号化を実行

    wc_FreeRsaKey(&enc);
    \endcode

    \sa wc_InitRsaKey
*/
int  wc_FreeRsaKey(RsaKey* key);

/*!
    \ingroup RSA

    \brief パディングなしでRSA操作を直接実行する関数。入力サイズはキーサイズと一致する必要があります。通常、これはRSA入力に既にパディングが行われている場合に使用されます。

    \return size 暗号化に成功した場合、暗号化されたバッファのサイズが返されます
    \return RSA_BUFFER_E RSAバッファエラー、出力が小さすぎるか入力が大きすぎます

    \param in 操作を行うバッファ
    \param inLen 入力バッファの長さ
    \param out 結果を保持するバッファ
    \param outSz 結果バッファのサイズに設定されます。出力バッファの長さとして渡す必要があります。ポインタ「out」がnullの場合、outSzは必要な予想バッファサイズに設定され、LENGTH_ONLY_Eが返されます。
    \param key 暗号化/復号に使用する初期化されたRSAキー
    \param type 秘密鍵または公開鍵を使用する場合（RSA_PUBLIC_ENCRYPT、RSA_PUBLIC_DECRYPT、RSA_PRIVATE_ENCRYPT、RSA_PRIVATE_DECRYPT）
    \param rng 初期化されたWC_RNG構造体

    _Example_
    \code
    int ret;
    WC_RNG rng;
    RsaKey key;
    byte  in[256];
    byte out[256];
    word32 outSz = (word32)sizeof(out);
    …

    ret = wc_RsaDirect(in, (word32)sizeof(in), out, &outSz, &key,
        RSA_PRIVATE_ENCRYPT, &rng);
    if (ret < 0) {
	    // エラーを処理
    }
    \endcode

    \sa wc_RsaPublicEncrypt
    \sa wc_RsaPrivateDecrypt
*/
int wc_RsaDirect(const byte* in, word32 inLen, byte* out, word32* outSz,
        RsaKey* key, int type, WC_RNG* rng);

/*!
    \ingroup RSA

    \brief この関数は、inからメッセージを暗号化し、結果をoutに格納します。初期化された公開鍵と乱数ジェネレータが必要です。副作用として、この関数はoutに書き込まれたバイト数をoutLenで返します。

    \return Success 入力メッセージの暗号化に成功した場合、成功時に書き込まれたバイト数を返し、失敗の場合はゼロ未満を返します。
    \return BAD_FUNC_ARG いずれかの入力パラメータが無効な場合に返されます
    \return RSA_BUFFER_E 出力バッファが暗号文を格納するには小さすぎる場合に返されます
    \return RNG_FAILURE_E 提供されたRNG構造体を使用してランダムブロックを生成する際にエラーがある場合に返されます
    \return MP_INIT_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_READ_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_CMP_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_INVMOD_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MOD_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MUL_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_ADD_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MULMOD_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_TO_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MEM メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_ZERO_E メッセージの暗号化中に使用される数学ライブラリにエラーがある場合に返される可能性があります

    \param in 暗号化する入力メッセージを含むバッファへのポインタ
    \param inLen 暗号化するメッセージの長さ
    \param out 出力暗号文を格納するバッファへのポインタ
    \param outLen 出力バッファの長さ
    \param key 暗号化に使用する公開鍵を含むRsaKey構造体へのポインタ
    \param rng ランダムブロックパディングを生成するRNG構造体

    _Example_
    \code
    RsaKey pub;
    int ret = 0;
    byte n[] = { // 受信した公開鍵のn成分で初期化 };
    byte e[] = { // 受信した公開鍵のe成分で初期化 };
    byte msg[] = { // 暗号化するメッセージの平文で初期化 };
    byte cipher[256]; // 256バイトは2048ビットRSA暗号文を格納するのに十分な大きさ

    wc_InitRsaKey(&pub, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), &pub);
    // 受信した公開鍵パラメータで初期化
    ret = wc_RsaPublicEncrypt(msg, sizeof(msg), out, sizeof(out), &pub, &rng);
    if ( ret != 0 ) {
    	// メッセージの暗号化エラー
    }
    \endcode

    \sa wc_RsaPrivateDecrypt
*/
int  wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                 word32 outLen, RsaKey* key, WC_RNG* rng);

/*!
    \ingroup RSA

    \brief この関数は、復号のためにwc_RsaPrivateDecrypt関数によって使用されます。

    \return Success 復号されたデータの長さ。
    \return RSA_PAD_E RsaUnPadエラー、フォーマットが不正

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out 復号されたデータを格納するバイト配列。
    \param key 復号に使用するキー。

    _Example_
    \code
    なし
    \endcode

    \sa wc_RsaPrivateDecrypt
*/
int  wc_RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out,
                                        RsaKey* key);

/*!
    \ingroup RSA

    \brief この関数は、プライベートRSA復号を提供します。

    \return Success 復号されたデータの長さ。
    \return MEMORY_E -125、メモリ不足エラー
    \return BAD_FUNC_ARG -173、不正な関数引数が提供されました

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out 復号されたデータを格納するバイト配列。
    \param outLen outの長さ。
    \param key 復号に使用するキー。

    _Example_
    \code
    ret = wc_RsaPublicEncrypt(in, inLen, out, sizeof(out), &key, &rng);
    if (ret < 0) {
        return -1;
    }
    ret = wc_RsaPrivateDecrypt(out, ret, plain, sizeof(plain), &key);
    if (ret < 0) {
        return -1;
    }
    \endcode

    \sa RsaUnPad
    \sa wc_RsaFunction
    \sa wc_RsaPrivateDecryptInline
*/
int  wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                  word32 outLen, RsaKey* key);

/*!
    \ingroup RSA

    \brief 秘密鍵で提供された配列に署名します。

    \return RSA_BUFFER_E: -131、RSAバッファエラー、出力が小さすぎるか入力が大きすぎます

    \param in 暗号化されるバイト配列。
    \param inLen inの長さ。
    \param out 暗号化されたデータを格納するバイト配列。
    \param outLen outの長さ。
    \param key 暗号化に使用するキー。
    \param RNG 乱数の目的で使用するRNG構造体。

    _Example_
    \code
    ret = wc_RsaSSL_Sign(in, inLen, out, sizeof(out), &key, &rng);
    if (ret < 0) {
        return -1;
    }
    memset(plain, 0, sizeof(plain));
    ret = wc_RsaSSL_Verify(out, ret, plain, sizeof(plain), &key);
    if (ret < 0) {
        return -1;
    }
    if (ret != inLen) {
        return -1;
    }
    if (XMEMCMP(in, plain, ret) != 0) {
        return -1;
    }
    \endcode

    \sa wc_RsaPad
*/
int  wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, WC_RNG* rng);

/*!
    \ingroup RSA

    \brief メッセージがRSAキーによって署名されたことを検証するために使用されます。出力は入力と同じバイト配列を使用します。

    \return >0 テキストの長さ。
    \return <0 エラーが発生しました。

    \param in 復号されるバイト配列。
    \param inLen 入力バッファの長さ。
    \param out 復号された情報へのポインタへのポインタ。
    \param key 使用するRsaKey。

    _Example_
    \code
    RsaKey key;
    WC_RNG rng;
    int ret = 0;
    long e = 65537; // 指数に使用する標準値
    wc_InitRsaKey(&key, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    wc_InitRng(&rng);
    wc_MakeRsaKey(&key, 2048, e, &rng);

    byte in[] = { // RSA暗号化情報で初期化 }
    byte* out;
    if(wc_RsaSSL_VerifyInline(in, sizeof(in), &out, &key) < 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_RsaSSL_Verify
    \sa wc_RsaSSL_Sign
*/
int  wc_RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out,
                                    RsaKey* key);

/*!
    \ingroup RSA

    \brief メッセージがキーによって署名されたことを検証するために使用されます。

    \return Success エラーがない場合のテキストの長さ。
    \return MEMORY_E メモリ例外。

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out 復号されたデータを格納するバイト配列。
    \param outLen outの長さ。
    \param key 検証に使用するキー。

    _Example_
    \code
    ret = wc_RsaSSL_Sign(in, inLen, out, sizeof(out), &key, &rng);
    if (ret < 0) {
        return -1;
    }
    memset(plain, 0, sizeof(plain));
    ret = wc_RsaSSL_Verify(out, ret, plain, sizeof(plain), &key);
    if (ret < 0) {
        return -1;
    }
    if (ret != inLen) {
        return -1;
    }
    if (XMEMCMP(in, plain, ret) != 0) {
        return -1;
    }
    \endcode

    \sa wc_RsaSSL_Sign
*/
int  wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                              word32 outLen, RsaKey* key);

/*!
    \ingroup RSA

    \brief 秘密鍵で提供された配列に署名します。

    \return RSA_BUFFER_E: -131、RSAバッファエラー、出力が小さすぎるか入力が大きすぎます

    \param in 暗号化されるバイト配列。
    \param inLen inの長さ。
    \param out 暗号化されたデータを格納するバイト配列。
    \param outLen outの長さ。
    \param hash メッセージに含まれるハッシュタイプ
    \param mgf マスク生成関数識別子
    \param key 検証に使用するキー。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;

    ret = wc_RsaPSS_Sign((byte*)szMessage, (word32)XSTRLEN(szMessage)+1,
            pSignature, sizeof(pSignature),
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
    if (ret > 0 ){
        sz = ret;
    } else return -1;

    ret = wc_RsaPSS_Verify(pSignature, sz, pt, outLen,
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key);
    if (ret <= 0)return -1;

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Verify
    \sa wc_RsaSetRNG
*/
int  wc_RsaPSS_Sign(const byte* in, word32 inLen, byte* out,
                                word32 outLen, enum wc_HashType hash, int mgf,
                                RsaKey* key, WC_RNG* rng);

/*!
    \ingroup RSA

    \brief メッセージがキーによって署名されたことを検証するために入力署名を復号します。WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return Success エラーがない場合のテキストの長さ。
    \return MEMORY_E メモリ例外。
    \return MP_EXPTMOD_E - fastmathを使用していて、FP_MAX_BITSがキーサイズの少なくとも2倍に設定されていない場合（例：4096ビットキーを使用する場合、FP_MAX_BITSを8192以上の値に設定）

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out 復号されたデータを格納するバイト配列。
    \param outLen outの長さ。
    \param hash メッセージに含まれるハッシュタイプ
    \param mgf マスク生成関数識別子
    \param key 検証に使用するキー。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;
    ret = wc_RsaPSS_Sign((byte*)szMessage, (word32)XSTRLEN(szMessage)+1,
            pSignature, sizeof(pSignature),
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
    if (ret > 0 ){
        sz = ret;
    } else return -1;

    ret = wc_RsaPSS_Verify(pSignature, sz, pt, outLen,
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key);
    if (ret <= 0)return -1;

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_VerifyInline
    \sa wc_RsaPSS_CheckPadding
    \sa wc_RsaSetRNG
*/
int  wc_RsaPSS_Verify(const byte* in, word32 inLen, byte* out,
                                  word32 outLen, enum wc_HashType hash, int mgf,
                                  RsaKey* key);

/*!
    \ingroup RSA

    \brief メッセージがRSAキーによって署名されたことを検証するために入力署名を復号します。出力は入力と同じバイト配列を使用します。WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return >0 テキストの長さ。
    \return <0 エラーが発生しました。

    \param in 復号されるバイト配列。
    \param inLen 入力バッファの長さ。
    \param out PSSデータを含むアドレスへのポインタ。
    \param hash メッセージに含まれるハッシュタイプ
    \param mgf マスク生成関数識別子
    \param key 使用するRsaKey。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;
    ret = wc_RsaPSS_Sign(digest, digestSz, pSignature, pSignatureSz,
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
    if (ret > 0 ){
        sz = ret;
    } else return -1;

    ret = wc_RsaPSS_VerifyInline(pSignature, sz, pt,
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key);
    if (ret <= 0)return -1;

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Verify
    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_VerifyCheck
    \sa wc_RsaPSS_VerifyCheck_ex
    \sa wc_RsaPSS_VerifyCheckInline
    \sa wc_RsaPSS_VerifyCheckInline_ex
    \sa wc_RsaPSS_CheckPadding
    \sa wc_RsaPSS_CheckPadding_ex
    \sa wc_RsaSetRNG
*/


int  wc_RsaPSS_VerifyInline(byte* in, word32 inLen, byte** out,
                                        enum wc_HashType hash, int mgf,
                                        RsaKey* key);
/*!
    \ingroup RSA

    \brief RSA-PSSで署名されたメッセージを検証します。ソルトの長さはハッシュの長さと等しくなります。WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return the length of the PSS data 成功時はPSSデータの長さ、失敗を示す負の値。
    \return MEMORY_E メモリ例外。

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out PSSデータを含むアドレスへのポインタ。
    \param outLen outの長さ。
    \param digest 検証されるデータのハッシュ。
    \param digestLen ハッシュの長さ。
    \param hash ハッシュアルゴリズム。
    \param mgf マスク生成関数。
    \param key 公開RSAキー。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;

    if (ret == 0) {
        digestSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
        ret = wc_Hash(WC_HASH_TYPE_SHA256, message, sz, digest, digestSz);
    } else return -1;

    if (ret == 0) {
        ret = wc_RsaPSS_Sign(digest, digestSz, pSignature, pSignatureSz,
                WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
        if (ret > 0 ){
            sz = ret;
        } else return -1;
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaPSS_VerifyCheck(pSignature, sz, pt, outLen,
                digest, digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key);
            if (ret <= 0) return -1;
    } else return -1;

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_Verify
    \sa wc_RsaPSS_VerifyCheck_ex
    \sa wc_RsaPSS_VerifyCheckInline
    \sa wc_RsaPSS_VerifyCheckInline_ex
    \sa wc_RsaPSS_CheckPadding
    \sa wc_RsaPSS_CheckPadding_ex
    \sa wc_RsaSetRNG
*/

int  wc_RsaPSS_VerifyCheck(const byte* in, word32 inLen,
                               byte* out, word32 outLen,
                               const byte* digest, word32 digestLen,
                               enum wc_HashType hash, int mgf,
                               RsaKey* key);
/*!
    \ingroup RSA

    \brief RSA-PSSで署名されたメッセージを検証します。WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return the length of the PSS data 成功時はPSSデータの長さ、失敗を示す負の値。
    \return MEMORY_E メモリ例外。

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out PSSデータを含むアドレスへのポインタ。
    \param outLen outの長さ。
    \param digest 検証されるデータのハッシュ。
    \param digestLen ハッシュの長さ。
    \param hash ハッシュアルゴリズム。
    \param mgf マスク生成関数。
    \param saltLen 使用されるソルトの長さ。RSA_PSS_SALT_LEN_DEFAULT（-1）は、ソルトの長さがハッシュの長さと同じであることを示します。RSA_PSS_SALT_LEN_DISCOVERは、ソルトの長さがデータから決定されることを示します。

    \param key 公開RSAキー。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;

    if (ret == 0) {
        digestSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
        ret = wc_Hash(WC_HASH_TYPE_SHA256, message, sz, digest, digestSz);
    } else return -1;

    if (ret == 0) {
        ret = wc_RsaPSS_Sign(digest, digestSz, pSignature, pSignatureSz,
                WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
        if (ret > 0 ){
            sz = ret;
        } else return -1;
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaPSS_VerifyCheck_ex(pSignature, sz, pt, outLen,
                digest, digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, saltLen, &key);
            if (ret <= 0) return -1;
    } else return -1;

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_Verify
    \sa wc_RsaPSS_VerifyCheck
    \sa wc_RsaPSS_VerifyCheckInline
    \sa wc_RsaPSS_VerifyCheckInline_ex
    \sa wc_RsaPSS_CheckPadding
    \sa wc_RsaPSS_CheckPadding_ex
    \sa wc_RsaSetRNG
*/
int  wc_RsaPSS_VerifyCheck_ex(byte* in, word32 inLen,
                               byte* out, word32 outLen,
                               const byte* digest, word32 digestLen,
                               enum wc_HashType hash, int mgf, int saltLen,
                               RsaKey* key);

/*!
    \ingroup RSA

    \brief RSA-PSSで署名されたメッセージを検証します。入力バッファは出力バッファとして再利用されます。ソルトの長さはハッシュの長さと等しくなります。

    WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return the length of the PSS data 成功時はPSSデータの長さ、失敗を示す負の値。

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out 復号されたデータを格納するバイト配列。
    \param digest 検証されるデータのハッシュ。
    \param digestLen ハッシュの長さ。
    \param hash メッセージに含まれるハッシュタイプ
    \param mgf マスク生成関数識別子
    \param key 検証に使用するキー。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;

    if (ret == 0) {
        digestSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
        ret = wc_Hash(WC_HASH_TYPE_SHA256, message, sz, digest, digestSz);
    } else return -1;

    if (ret == 0) {
        ret = wc_RsaPSS_Sign(digest, digestSz, pSignature, pSignatureSz,
                WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
        if (ret > 0 ){
            sz = ret;
        } else return -1;
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaPSS_VerifyCheckInline(pSignature, sz, pt,
                digest, digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key);
            if (ret <= 0) return -1;
    } else return -1;

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_Verify
    \sa wc_RsaPSS_VerifyCheck
    \sa wc_RsaPSS_VerifyCheck_ex
    \sa wc_RsaPSS_VerifyCheckInline_ex
    \sa wc_RsaPSS_CheckPadding
    \sa wc_RsaPSS_CheckPadding_ex
    \sa wc_RsaSetRNG
*/
int  wc_RsaPSS_VerifyCheckInline(byte* in, word32 inLen, byte** out,
                               const byte* digest, word32 digentLen,
                               enum wc_HashType hash, int mgf,
                               RsaKey* key);
/*!
    \ingroup RSA

    \brief RSA-PSSで署名されたメッセージを検証します。入力バッファは出力バッファとして再利用されます。WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return the length of the PSS data 成功時はPSSデータの長さ、失敗を示す負の値。

    \param in 復号されるバイト配列。
    \param inLen inの長さ。
    \param out 復号されたデータを格納するバイト配列。
    \param digest 検証されるデータのハッシュ。
    \param digestLen ハッシュの長さ。
    \param hash メッセージに含まれるハッシュタイプ
    \param mgf マスク生成関数識別子
    \param saltLen 使用されるソルトの長さ。RSA_PSS_SALT_LEN_DEFAULT（-1）は、ソルトの長さがハッシュの長さと同じであることを示します。RSA_PSS_SALT_LEN_DISCOVERは、ソルトの長さがデータから決定されることを示します。
    \param key 検証に使用するキー。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;

    if (ret == 0) {
        digestSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
        ret = wc_Hash(WC_HASH_TYPE_SHA256, message, sz, digest, digestSz);
    } else return -1;

    if (ret == 0) {
        ret = wc_RsaPSS_Sign(digest, digestSz, pSignature, pSignatureSz,
                WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
        if (ret > 0 ){
            sz = ret;
        } else return -1;
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaPSS_VerifyCheckInline_ex(pSignature, sz, pt,
                digest, digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, saltLen, &key);
            if (ret <= 0) return -1;
    } else return -1;

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_Verify
    \sa wc_RsaPSS_VerifyCheck
    \sa wc_RsaPSS_VerifyCheck_ex
    \sa wc_RsaPSS_VerifyCheckInline
    \sa wc_RsaPSS_CheckPadding
    \sa wc_RsaPSS_CheckPadding_ex
    \sa wc_RsaSetRNG
*/
int  wc_RsaPSS_VerifyCheckInline_ex(byte* in, word32 inLen, byte** out,
                               const byte* digest, word32 digentLen,
                               enum wc_HashType hash, int mgf, int saltLen,
                               RsaKey* key);

/*!
    \ingroup RSA

    \brief 署名が一致することを確認するためにPSSデータをチェックします。ソルトの長さはハッシュの長さと等しくなります。WC_RSA_BLINDINGが有効になっている場合、キーはwc_RsaSetRNGによってRNGと関連付ける必要があります。

    \return BAD_PADDING_E PSSデータが無効な場合、BAD_FUNC_ARG inまたはsigにNULLが渡された場合、またはinSzがハッシュアルゴリズムの長さと同じでない場合、成功時は0。
    \return MEMORY_E メモリ例外。

    \param in 検証されるデータのハッシュ。
    \param inSz ハッシュの長さ。
    \param sig PSSデータを保持するバッファ。
    \param sigSz PSSデータのサイズ。
    \param hashType ハッシュアルゴリズム。

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;
    if (ret == 0) {
        digestSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
        ret = wc_Hash(WC_HASH_TYPE_SHA256, message, sz, digest, digestSz);
    } else return -1;
    ret = wc_RsaPSS_Sign(digest, digestSz, pSignature, sizeof(pSignature),
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
    if (ret > 0 ){
        sz = ret;
    } else return -1;

    verify = wc_RsaPSS_Verify(pSignature, sz, out, outLen,
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key);
    if (verify <= 0)return -1;

    ret = wc_RsaPSS_CheckPadding(digest, digestSz, out, verify, hash);

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_Verify
    \sa wc_RsaPSS_VerifyInline
    \sa wc_RsaPSS_VerifyCheck
    \sa wc_RsaPSS_VerifyCheck_ex
    \sa wc_RsaPSS_VerifyCheckInline
    \sa wc_RsaPSS_VerifyCheckInline_ex
    \sa wc_RsaPSS_CheckPadding_ex
    \sa wc_RsaSetRNG
*/
int  wc_RsaPSS_CheckPadding(const byte* in, word32 inLen, const byte* sig,
                                        word32 sigSz,
                                        enum wc_HashType hashType);
/*!
    \ingroup RSA

    \brief 署名が一致することを確認するためにPSSデータをチェックします。ソルトの長さはハッシュの長さと等しくなります。

    \return BAD_PADDING_E PSSデータが無効な場合、BAD_FUNC_ARG inまたはsigにNULLが渡された場合、またはinSzがハッシュアルゴリズムの長さと同じでない場合、成功時は0。
    \return MEMORY_E メモリ例外。

    \param in        検証されるデータのハッシュ。
    \param inSz      ハッシュの長さ。
    \param sig       PSSデータを保持するバッファ。
    \param sigSz     PSSデータのサイズ。
    \param hashType  ハッシュアルゴリズム。
    \param saltLen   使用されるソルトの長さ。RSA_PSS_SALT_LEN_DEFAULT（-1）は、ソルトの長さがハッシュの長さと同じであることを示します。RSA_PSS_SALT_LEN_DISCOVERは、ソルトの長さがデータから決定されることを示します。
    \param bits      FIPSの場合、ソルトサイズの計算に使用できます

    _Example_
    \code
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
    } else return -1;
    if (ret == 0) {
        ret = wc_RsaSetRNG(&key, &rng);
    } else return -1;
    if (ret == 0) {
            ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    } else return -1;
    if (ret == 0) {
        digestSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
        ret = wc_Hash(WC_HASH_TYPE_SHA256, message, sz, digest, digestSz);
    } else return -1;
    ret = wc_RsaPSS_Sign(digest, digestSz, pSignature, sizeof(pSignature),
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
    if (ret > 0 ){
        sz = ret;
    } else return -1;

    verify = wc_RsaPSS_Verify(pSignature, sz, out, outLen,
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key);
    if (verify <= 0)return -1;

    ret = wc_RsaPSS_CheckPadding_ex(digest, digestSz, out, verify, hash, saltLen, 0);

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_RsaPSS_Sign
    \sa wc_RsaPSS_Verify
    \sa wc_RsaPSS_VerifyInline
    \sa wc_RsaPSS_VerifyCheck
    \sa wc_RsaPSS_VerifyCheck_ex
    \sa wc_RsaPSS_VerifyCheckInline
    \sa wc_RsaPSS_VerifyCheckInline_ex
    \sa wc_RsaPSS_CheckPadding
*/
int  wc_RsaPSS_CheckPadding_ex(const byte* in, word32 inLen, const byte* sig,
                word32 sigSz, enum wc_HashType hashType, int saltLen, int bits);
/*!
    \ingroup RSA

    \brief 提供されたキー構造体の暗号化サイズを返します。

    \return Success 提供されたキー構造体の暗号化サイズ。

    \param key 検証に使用するキー。

    _Example_
    \code
    int sz = wc_RsaEncryptSize(&key);
    \endcode

    \sa wc_InitRsaKey
    \sa wc_InitRsaKey_ex
    \sa wc_MakeRsaKey
*/
int  wc_RsaEncryptSize(const RsaKey* key);

/*!
    \ingroup RSA

    \brief この関数は、DER形式のRSA秘密鍵を解析し、秘密鍵を抽出して、指定されたRsaKey構造体に格納します。また、idxに解析された距離を設定します。

    \return 0 DERエンコードされた入力から秘密鍵を正常に解析した場合に返されます
    \return ASN_PARSE_E 入力バッファから秘密鍵を解析する際にエラーがある場合に返されます。これは、入力秘密鍵がASN.1標準に従って適切にフォーマットされていない場合に発生する可能性があります
    \return ASN_RSA_KEY_E RSAキー入力の秘密鍵要素を読み取る際にエラーがある場合に返されます

    \param input デコードするDER形式の秘密鍵を含むバッファへのポインタ
    \param inOutIdx キーが始まるバッファ内のインデックスへのポインタ（通常は0）。この関数の副作用として、inOutIdxは入力バッファを通じて解析された距離を格納します
    \param key デコードされた秘密鍵を格納するRsaKey構造体へのポインタ
    \param inSz 入力バッファのサイズ

    _Example_
    \code
    RsaKey enc;
    word32 idx = 0;
    int ret = 0;
    byte der[] = { // DERエンコードされたRSA秘密鍵で初期化 };

    wc_InitRsaKey(&enc, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    ret = wc_RsaPrivateKeyDecode(der, &idx, &enc, sizeof(der));
    if( ret != 0 ) {
    	// 秘密鍵の解析エラー
    }
    \endcode

    \sa wc_RsaPublicKeyDecode
    \sa wc_MakeRsaKey
*/
int  wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
                            RsaKey* key, word32 inSz);

/*!
    \ingroup RSA

    \brief この関数は、DER形式のRSA公開鍵を解析し、公開鍵を抽出して、指定されたRsaKey構造体に格納します。また、idxに解析された距離を設定します。

    \return 0 DERエンコードされた入力から公開鍵を正常に解析した場合に返されます
    \return ASN_PARSE_E 入力バッファから公開鍵を解析する際にエラーがある場合に返されます。これは、入力公開鍵がASN.1標準に従って適切にフォーマットされていない場合に発生する可能性があります
    \return ASN_OBJECT_ID_E ASN.1オブジェクトIDがRSA公開鍵のものと一致しない場合に返されます
    \return ASN_EXPECT_0_E 入力キーがASN.1標準に従って正しくフォーマットされていない場合に返されます
    \return ASN_BITSTR_E 入力キーがASN.1標準に従って正しくフォーマットされていない場合に返されます
    \return ASN_RSA_KEY_E RSAキー入力の公開鍵要素を読み取る際にエラーがある場合に返されます

    \param input デコードする入力DERエンコードされたRSA公開鍵を含むバッファへのポインタ
    \param inOutIdx キーが始まるバッファ内のインデックスへのポインタ（通常は0）。この関数の副作用として、inOutIdxは入力バッファを通じて解析された距離を格納します
    \param key デコードされた公開鍵を格納するRsaKey構造体へのポインタ
    \param inSz 入力バッファのサイズ

    _Example_
    \code
    RsaKey pub;
    word32 idx = 0;
    int ret = 0;
    byte der[] = { // DERエンコードされたRSA公開鍵で初期化 };

    wc_InitRsaKey(&pub, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    ret = wc_RsaPublicKeyDecode(der, &idx, &pub, sizeof(der));
    if( ret != 0 ) {
    	// 公開鍵の解析エラー
    }
    \endcode

    \sa wc_RsaPublicKeyDecodeRaw
*/
int  wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx,
                           RsaKey* key, word32 inSz);

/*!
    \ingroup RSA

    \brief この関数は、RSA公開鍵の生の要素をデコードし、公開モジュラス（n）と指数（e）を受け取ります。これらの生の要素を提供されたRsaKey構造体に格納し、暗号化/復号プロセスでそれらを使用できるようにします。

    \return 0 公開鍵の生の要素をRsaKey構造体に正常にデコードした場合に返されます
    \return BAD_FUNC_ARG いずれかの入力引数がNULLと評価された場合に返されます
    \return MP_INIT_E 多精度整数（mp_int）ライブラリで使用するために整数を初期化する際にエラーがある場合に返されます
    \return ASN_GETINT_E 提供されたRSAキー要素（nまたはe）のいずれかを読み取る際にエラーがある場合に返されます

    \param n 公開RSAキーの生のモジュラスパラメータを含むバッファへのポインタ
    \param nSz nを含むバッファのサイズ
    \param e 公開RSAキーの生の指数パラメータを含むバッファへのポインタ
    \param eSz eを含むバッファのサイズ
    \param key 提供された公開鍵要素で初期化するRsaKey構造体へのポインタ

    _Example_
    \code
    RsaKey pub;
    int ret = 0;
    byte n[] = { // 受信した公開鍵のn成分で初期化 };
    byte e[] = { // 受信した公開鍵のe成分で初期化 };

    wc_InitRsaKey(&pub, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), &pub);
    if( ret != 0 ) {
    	// 公開鍵要素の解析エラー
    }
    \endcode

    \sa wc_RsaPublicKeyDecode
*/
int  wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz,
                                        const byte* e, word32 eSz, RsaKey* key);

/*!
    \ingroup RSA

    \brief この関数は、RsaKeyキーをDER形式に変換します。結果はoutputに書き込まれ、書き込まれたバイト数を返します。

    \return >0 成功、書き込まれたバイト数。
    \return BAD_FUNC_ARG keyまたはoutputがnullの場合、またはkey->typeがRSA_PRIVATEでない場合、またはinLenが出力バッファに対して十分な大きさでない場合に返されます。
    \return MEMORY_E メモリの割り当て中にエラーがある場合に返されます。

    \param key 初期化されたRsaKey構造体。
    \param output 出力バッファへのポインタ。
    \param inLen 出力バッファのサイズ。

    _Example_
    \code
    byte* der;
    // derにメモリを割り当て
    int derSz = // derに割り当てられたメモリの量;
    RsaKey key;
    WC_RNG rng;
    long e = 65537; // 指数に使用する標準値
    ret = wc_MakeRsaKey(&key, 2048, e, &rng); // 2048ビット長の秘密鍵を生成
    wc_InitRsaKey(&key, NULL);
    wc_InitRng(&rng);
    if(wc_RsaKeyToDer(&key, der, derSz) != 0)
    {
        // スローされたエラーを処理
    }
    \endcode

    \sa wc_RsaKeyToPublicDer
    \sa wc_InitRsaKey
    \sa wc_MakeRsaKey
    \sa wc_InitRng
*/
int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup RSA

    \brief この関数は、使用するパディングを選択できるようにしながら、RSA暗号化を実行します。
    \return size 暗号化に成功した場合、暗号化されたバッファのサイズが返されます
    \return RSA_BUFFER_E RSAバッファエラー、出力が小さすぎるか入力が大きすぎます

    \param in 暗号化するバッファへのポインタ
    \param inLen 暗号化するバッファの長さ
    \param out 作成された暗号化されたメッセージ
    \param outLen 暗号化されたメッセージを保持するために利用可能なバッファの長さ
    \param key 初期化されたRSAキー構造体
    \param rng 初期化されたWC_RNG構造体
    \param type 使用するパディングのタイプ（WC_RSA_OAEP_PADまたはWC_RSA_PKCSV15_PAD）
    \param hash 使用するハッシュのタイプ（選択肢はhash.hにあります）
    \param mgf 使用するマスク生成関数のタイプ
    \param label 暗号化されたメッセージに関連付けるオプションのラベル
    \param labelSz 使用されるオプションのラベルのサイズ

    _Example_
    \code
    WC_RNG rng;
    RsaKey key;
    byte in[] = "I use Turing Machines to ask questions"
    byte out[256];
    int ret;
    …

    ret = wc_RsaPublicEncrypt_ex(in, sizeof(in), out, sizeof(out), &key, &rng,
    WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
    if (ret < 0) {
	    // エラーを処理
    }
    \endcode

    \sa wc_RsaPublicEncrypt
    \sa wc_RsaPrivateDecrypt_ex
*/
int  wc_RsaPublicEncrypt_ex(const byte* in, word32 inLen, byte* out,
                   word32 outLen, RsaKey* key, WC_RNG* rng, int type,
                   enum wc_HashType hash, int mgf, byte* label, word32 labelSz);

/*!
    \ingroup RSA

    \brief この関数は、RSAを使用してメッセージを復号し、どのパディングタイプを使用するかのオプションを提供します。

    \return size 復号に成功した場合、復号されたメッセージのサイズが返されます。
    \return MEMORY_E 必要な配列をmallocするのに十分なメモリがシステムにない場合に返されます。
    \return BAD_FUNC_ARG 関数に不正な引数が渡された場合に返されます。

    \param in 復号するバッファへのポインタ
    \param inLen 復号するバッファの長さ
    \param out 作成された復号されたメッセージ
    \param outLen 復号されたメッセージを保持するために利用可能なバッファの長さ
    \param key 初期化されたRSAキー構造体
    \param type 使用するパディングのタイプ（WC_RSA_OAEP_PADまたはWC_RSA_PKCSV15_PAD）
    \param hash 使用するハッシュのタイプ（選択肢はhash.hにあります）
    \param mgf 使用するマスク生成関数のタイプ
    \param label 暗号化されたメッセージに関連付けるオプションのラベル
    \param labelSz 使用されるオプションのラベルのサイズ

    _Example_
    \code
    WC_RNG rng;
    RsaKey key;
    byte in[] = "I use Turing Machines to ask questions"
    byte out[256];
    byte plain[256];
    int ret;
    …
    ret = wc_RsaPublicEncrypt_ex(in, sizeof(in), out, sizeof(out), &key,
    &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
    if (ret < 0) {
	    // エラーを処理
    }
    …
    ret = wc_RsaPrivateDecrypt_ex(out, ret, plain, sizeof(plain), &key,
    WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);

    if (ret < 0) {
	    // エラーを処理
    }
    \endcode

    \sa なし
*/
int  wc_RsaPrivateDecrypt_ex(const byte* in, word32 inLen,
                   byte* out, word32 outLen, RsaKey* key, int type,
                   enum wc_HashType hash, int mgf, byte* label, word32 labelSz);

/*!
    \ingroup RSA

    \brief この関数は、RSAを使用してメッセージをインラインで復号し、どのパディングタイプを使用するかのオプションを提供します。inバッファは呼び出し後に復号されたメッセージを含み、outバイトポインタは平文がある「in」バッファ内の場所を指します。

    \return size 復号に成功した場合、復号されたメッセージのサイズが返されます。
    \return MEMORY_E: 必要な配列をmallocするのに十分なメモリがシステムにない場合に返されます。
    \return RSA_PAD_E: パディングにエラーがあった場合に返されます。
    \return BAD_PADDING_E: パディングを解析中にエラーが発生した場合に返されます。
    \return BAD_FUNC_ARG: 関数に不正な引数が渡された場合に返されます。

    \param in 復号するバッファへのポインタ
    \param inLen 復号するバッファの長さ
    \param out 「in」バッファ内の復号されたメッセージの場所へのポインタ
    \param key 初期化されたRSAキー構造体
    \param type 使用するパディングのタイプ（WC_RSA_OAEP_PADまたはWC_RSA_PKCSV15_PAD）
    \param hash 使用するハッシュのタイプ（選択肢はhash.hにあります）
    \param mgf 使用するマスク生成関数のタイプ
    \param label 暗号化されたメッセージに関連付けるオプションのラベル
    \param labelSz 使用されるオプションのラベルのサイズ

    _Example_
    \code
    WC_RNG rng;
    RsaKey key;
    byte in[] = "I use Turing Machines to ask questions"
    byte out[256];
    byte* plain;
    int ret;
    …
    ret = wc_RsaPublicEncrypt_ex(in, sizeof(in), out, sizeof(out), &key,
    &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);

    if (ret < 0) {
	    // エラーを処理
    }
    …
    ret = wc_RsaPrivateDecryptInline_ex(out, ret, &plain, &key,
    WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);

    if (ret < 0) {
	    // エラーを処理
    }
    \endcode

    \sa なし
*/
int  wc_RsaPrivateDecryptInline_ex(byte* in, word32 inLen,
                      byte** out, RsaKey* key, int type, enum wc_HashType hash,
                      int mgf, byte* label, word32 labelSz);

/*!
    \ingroup RSA

    \brief RsaKey構造体をRSAアルゴリズムに使用される個々の要素（e、n）に展開します。

    \return 0 関数がエラーなく正常に実行された場合に返されます。
    \return BAD_FUNC_ARG: いずれかのパラメータがnull値で渡された場合に返されます。
    \return RSA_BUFFER_E: 渡されたeまたはnバッファが正しいサイズでない場合に返されます。
    \return MP_MEM: 内部関数にメモリエラーがある場合に返されます。
    \return MP_VAL: 内部関数の引数が無効な場合に返されます。

    \param key 検証に使用するキー。
    \param e eの値のバッファ。eはRSAモジュラー演算における大きな正の整数です。
    \param eSz eバッファのサイズ。
    \param n nの値のバッファ。nはRSAモジュラー演算における大きな正の整数です。
    \param nSz nバッファのサイズ。

    _Example_
    \code
    Rsa key; // 有効なRSAキー。
    byte e[ バッファサイズ 例：256 ];
    byte n[256];
    int ret;
    word32 eSz = sizeof(e);
    word32 nSz = sizeof(n);
    ...
    ret = wc_RsaFlattenPublicKey(&key, e, &eSz, n, &nSz);
    if (ret != 0) {
    	// 失敗ケース。
    }
    \endcode

    \sa wc_InitRsaKey
    \sa wc_InitRsaKey_ex
    \sa wc_MakeRsaKey
*/
int  wc_RsaFlattenPublicKey(const RsaKey* key, byte* e, word32* eSz, byte* n,
                            word32* nSz);

/*!
    \ingroup RSA

    \brief RSA公開鍵をDER形式に変換します。outputに書き込み、書き込まれたバイト数を返します。

    \return >0 成功、書き込まれたバイト数。
    \return BAD_FUNC_ARG keyまたはoutputがnullの場合に返されます。
    \return MEMORY_E メモリの割り当て中にエラーが発生した場合に返されます。
    \return <0 エラー

    \param key 変換するRSAキー構造体。
    \param output DERを保持する出力バッファ。（NULLの場合は長さのみを返します）
    \param inLen バッファの長さ。

    _Example_
    \code
    RsaKey key;

    wc_InitRsaKey(&key, NULL);
    // キーを使用

    const int BUFFER_SIZE = 1024; // バッファに適切なサイズ
    byte output[BUFFER_SIZE];
    if (wc_RsaKeyToPublicDer(&key, output, sizeof(output)) != 0) {
        // エラーを処理
    }
    \endcode

    \sa wc_RsaPublicKeyDerSize
    \sa wc_RsaKeyToPublicDer_ex
    \sa wc_InitRsaKey
*/
int wc_RsaKeyToPublicDer(RsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup RSA

    \brief RSA公開鍵をDER形式に変換します。outputに書き込み、書き込まれたバイト数を返します。with_headerが0の場合、（seq + n + e）のみがASN.1 DER形式で返され、ヘッダーは除外されます。

    \return >0 成功、書き込まれたバイト数。
    \return BAD_FUNC_ARG keyまたはoutputがnullの場合に返されます。
    \return MEMORY_E メモリの割り当て中にエラーが発生した場合に返されます。
    \return <0 エラー

    \param key 変換するRSAキー構造体。
    \param output DERを保持する出力バッファ。（NULLの場合は長さのみを返します）
    \param inLen バッファの長さ。

    _Example_
    \code
    RsaKey key;

    wc_InitRsaKey(&key, NULL);
    // キーを使用

    const int BUFFER_SIZE = 1024; // バッファに適切なサイズ
    byte output[BUFFER_SIZE];
    if (wc_RsaKeyToPublicDer_ex(&key, output, sizeof(output), 0) != 0) {
        // エラーを処理
    }
    \endcode

    \sa wc_RsaPublicKeyDerSize
    \sa wc_RsaKeyToPublicDer
    \sa wc_InitRsaKey
*/
int wc_RsaKeyToPublicDer_ex(RsaKey* key, byte* output, word32 inLen,
    int with_header);

/*!
    \ingroup RSA

    \brief この関数は、長さsize（ビット単位）と指定された指数（e）のRSA秘密鍵を生成します。その後、このキーを提供されたRsaKey構造体に格納し、暗号化/復号に使用できるようにします。eに使用する安全な数値は65537です。sizeはRSA_MIN_SIZE以上かつRSA_MAX_SIZE以下である必要があります。この関数を使用するには、コンパイル時にオプションWOLFSSL_KEY_GENを有効にする必要があります。./configureを使用する場合は、--enable-keygenで実現できます。

    \return 0 RSA秘密鍵の生成に成功した場合に返されます
    \return BAD_FUNC_ARG いずれかの入力引数がNULLの場合、sizeパラメータが必要な境界外にある場合、またはeが誤って選択された場合に返されます
    \return RNG_FAILURE_E 提供されたRNG構造体を使用してランダムブロックを生成する際にエラーがある場合に返されます
    \return MP_INIT_E
    \return MP_READ_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_CMP_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_INVMOD_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_EXPTMOD_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MOD_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MUL_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_ADD_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MULMOD_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_TO_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_MEM RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります
    \return MP_ZERO_E RSAキーの生成中に使用される数学ライブラリにエラーがある場合に返される可能性があります

    \param key 生成された秘密鍵を格納するRsaKey構造体へのポインタ
    \param size 希望するキーの長さ（ビット単位）。RSA_MIN_SIZEより大きくRSA_MAX_SIZEより小さい必要があります
    \param e キーを生成するために使用する指数パラメータ。安全な選択肢は65537です
    \param rng キーを作成する際の乱数生成に使用するRNG構造体へのポインタ

    _Example_
    \code
    RsaKey priv;
    WC_RNG rng;
    int ret = 0;
    long e = 65537; // 指数に使用する標準値

    wc_InitRsaKey(&priv, NULL); // ヒープヒントを使用しない。カスタムメモリなし
    wc_InitRng(&rng);
    // 2048ビット長の秘密鍵を生成
    ret = wc_MakeRsaKey(&priv, 2048, e, &rng);
    if( ret != 0 ) {
	    // 秘密鍵の生成エラー
    }
    \endcode

    \sa なし
*/
int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng);

/*!
    \ingroup RSA

    \brief この関数は、ノンブロッキングRSAコンテキストを設定します。RsaNbコンテキストが設定されると、RSA関数を多くの小さな操作に分割する、高速数学ベースのノンブロッキングexptmodが有効になります。WC_RSA_NONBLOCKが定義されている場合に有効になります。

    \return 0 成功
    \return BAD_FUNC_ARG keyまたはnbがnullの場合に返されます。

    \param key RSAキー構造体
    \param nb このRSAキーが使用するRSAノンブロッキング構造体。

    _Example_
    \code
    int ret, count = 0;
    RsaKey key;
    RsaNb  nb;

    wc_InitRsaKey(&key, NULL);

    // ノンブロッキングRSAモードを有効化 - コンテキストを提供
    ret = wc_RsaSetNonBlock(key, &nb);
    if (ret != 0)
        return ret;

    do {
        ret = wc_RsaSSL_Sign(in, inLen, out, outSz, key, rng);
        count++; // ブロック回数を追跡
        if (ret == FP_WOULDBLOCK) {
            // ここで「その他の」作業を実行
        }
    } while (ret == FP_WOULDBLOCK);
    if (ret < 0) {
        return ret;
    }

    printf("RSAノンブロック署名: サイズ %d、%d回\n", ret, count);
    \endcode

    \sa wc_RsaSetNonBlockTime
*/
int wc_RsaSetNonBlock(RsaKey* key, RsaNb* nb);

/*!
    \ingroup RSA

    \brief この関数は、最大ブロッキング時間をマイクロ秒単位で設定します。CPU速度（メガヘルツ単位）とともに事前計算されたテーブル（tfm.c exptModNbInstを参照）を使用して、次の操作が提供された最大ブロッキング時間内に完了できるかどうかを判断します。WC_RSA_NONBLOCK_TIMEが定義されている場合に有効になります。

    \return 0 成功
    \return BAD_FUNC_ARG keyがnullの場合、またはwc_RsaSetNonBlockが事前に呼び出されておらずkey->nbがnullの場合に返されます。

    \param key RSAキー構造体。
    \param maxBlockUs 最大ブロック時間（マイクロ秒）。
    \param cpuMHz CPU速度（メガヘルツ単位）。

    _Example_
    \code
    RsaKey key;
    RsaNb  nb;

    wc_InitRsaKey(&key, NULL);
    wc_RsaSetNonBlock(key, &nb);
    wc_RsaSetNonBlockTime(&key, 4000, 160); // Block Max = 4 ms、CPU = 160MHz

    \endcode

    \sa wc_RsaSetNonBlock
*/
int wc_RsaSetNonBlockTime(RsaKey* key, word32 maxBlockUs,
    word32 cpuMHz);
