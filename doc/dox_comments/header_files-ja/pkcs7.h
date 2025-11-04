/*!
    \ingroup PKCS7

    \brief カスタムAES鍵ラップ/アンラップ操作に使用されるコールバック。

    \return 成功時には、出力バッファに書き込まれたラップ/アンラップされた鍵のサイズを返す必要があります。戻り値0またはエラーコード（< 0）は失敗を示します。

    \param[in] key 使用する鍵を指定します。
    \param[in] keySz 使用する鍵のサイズ。
    \param[in] in ラップ/アンラップする入力データを指定します。
    \param[in] inSz 入力データのサイズ。
    \param[in] wrap 要求された操作が鍵ラップの場合は1、アンラップの場合は0。
    \param[out] out 出力バッファを指定します。
    \param[out] outSz 出力バッファのサイズ。
*/
typedef int (*CallbackAESKeyWrapUnwrap)(const byte* key, word32 keySz,
        const byte* in, word32 inSz, int wrap, byte* out, word32 outSz);

/*!
    \ingroup PKCS7

    \brief この関数は、DER形式の証明書でPKCS7構造体を初期化します。空のPKCS7構造体を初期化するには、certにNULLを、certSzに0を渡すことができます。

    \return 0 PKCS7構造体の初期化に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリ割り当てエラーがある場合に返されます。
    \return ASN_PARSE_E 証明書ヘッダーの解析エラーがある場合に返されます。
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプの解析エラーがある場合に返されます。
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます。
    \return ASN_BEFORE_DATE_E 日付が証明書開始日より前の場合に返されます。
    \return ASN_AFTER_DATE_E 日付が証明書有効期限より後の場合に返されます。
    \return ASN_BITSTR_E 証明書からビット文字列の解析エラーがある場合に返されます。
    \return ECC_CURVE_OID_E 証明書からECC鍵の解析エラーがある場合に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が不明な鍵オブジェクトIDを使用している場合に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます。
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます。
    \return ASN_CRIT_EXT_E 証明書の処理中に不明なクリティカル拡張に遭遇した場合に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書署名の確認に失敗した場合に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約によって許可されていない場合に返されます。
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます。

    \param pkcs7 デコードされた証明書を格納するPKCS7構造体へのポインタ。
    \param cert PKCS7構造体を初期化するためのDER形式ASN.1証明書を含むバッファへのポインタ。
    \param certSz 証明書バッファのサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    byte derBuff[] = { }; // DERエンコードされた証明書で初期化
    if ( wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff)) != 0 ) {
    	// 証明書のpkcs7形式への解析エラー
    }
    \endcode

    \sa wc_PKCS7_Free
*/
int  wc_PKCS7_InitWithCert(PKCS7* pkcs7, byte* cert, word32 certSz);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7初期化子によって割り当てられたメモリを解放します。

    \return none 戻り値なし。

    \param pkcs7 解放するPKCS7構造体へのポインタ。

    _Example_
    \code
    PKCS7 pkcs7;
    // PKCS7オブジェクトを初期化して使用

    wc_PKCS7_Free(pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
void wc_PKCS7_Free(PKCS7* pkcs7);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7データコンテンツタイプをビルドし、PKCS7構造体を解析可能なPKCS7データパケットを含むバッファにエンコードします。

    \return Success PKCS7データをバッファに正常にエンコードした場合、PKCS7構造体で解析されたインデックスまで返します。このインデックスは、出力バッファに書き込まれたバイト数にも対応します。
    \return BUFFER_E 指定されたバッファがエンコードされた証明書を保持するのに十分な大きさでない場合に返されます。

    \param pkcs7 エンコードするPKCS7構造体へのポインタ。
    \param output エンコードされた証明書を格納するバッファへのポインタ。
    \param outputSz 出力バッファで利用可能なサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { }; // DERエンコードされた証明書で初期化
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // エンコードするメッセージとデータを更新
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... など

    ret = wc_PKCS7_EncodeData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
	    // 出力バッファへのエンコードエラー
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
int  wc_PKCS7_EncodeData(PKCS7* pkcs7, byte* output,
                                       word32 outputSz);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7署名付きデータコンテンツタイプをビルドし、PKCS7構造体を解析可能なPKCS7署名付きデータパケットを含むバッファにエンコードします。

    \return Success PKCS7データをバッファに正常にエンコードした場合、PKCS7構造体で解析されたインデックスまで返します。このインデックスは、出力バッファに書き込まれたバイト数にも対応します。
    \return BAD_FUNC_ARG 署名付きデータパケットを生成するために必要な1つ以上の要素がPKCS7構造体に欠けている場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return PUBLIC_KEY_E 公開鍵の解析エラーがある場合に返されます。
    \return RSA_BUFFER_E バッファエラー、出力が小さすぎるか入力が大きすぎる場合に返されます。
    \return BUFFER_E 指定されたバッファがエンコードされた証明書を保持するのに十分な大きさでない場合に返されます。
    \return MP_INIT_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_READ_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_CMP_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_INVMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_EXPTMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MUL_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_ADD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MULMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_TO_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MEM 署名の生成エラーがある場合に返される可能性があります。

    \param pkcs7 エンコードするPKCS7構造体へのポインタ。
    \param output エンコードされた証明書を格納するバッファへのポインタ。
    \param outputSz 出力バッファで利用可能なサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte data[] = {}; // 署名するデータで初期化
    byte derBuff[] = { }; // DERエンコードされた証明書で初期化
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // エンコードするメッセージとデータを更新
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    pkcs7.hashOID = SHAh;
    pkcs7.rng = &rng;
    ... など

    ret = wc_PKCS7_EncodeSignedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
    	// 出力バッファへのエンコードエラー
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_VerifySignedData
*/
int  wc_PKCS7_EncodeSignedData(PKCS7* pkcs7,
                                       byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7署名付きデータコンテンツタイプをビルドし、PKCS7構造体を解析可能なPKCS7署名付きデータパケットを含むヘッダーとフッターバッファにエンコードします。これにはコンテンツは含まれません。
    データのハッシュを計算して提供する必要があります。

    \return 0=Success
    \return BAD_FUNC_ARG 署名付きデータパケットを生成するために必要な1つ以上の要素がPKCS7構造体に欠けている場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return PUBLIC_KEY_E 公開鍵の解析エラーがある場合に返されます。
    \return RSA_BUFFER_E バッファエラー、出力が小さすぎるか入力が大きすぎる場合に返されます。
    \return BUFFER_E 指定されたバッファがエンコードされた証明書を保持するのに十分な大きさでない場合に返されます。
    \return MP_INIT_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_READ_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_CMP_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_INVMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_EXPTMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MUL_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_ADD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MULMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_TO_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MEM 署名の生成エラーがある場合に返される可能性があります。

    \param pkcs7 エンコードするPKCS7構造体へのポインタ。
    \param hashBuf コンテンツデータの計算されたハッシュへのポインタ。
    \param hashSz ダイジェストのサイズ。
    \param outputHead エンコードされた証明書ヘッダーを格納するバッファへのポインタ。
    \param outputHeadSz 出力ヘッダーバッファのサイズが入力され、実際のサイズを返します。
    \param outputFoot エンコードされた証明書フッターを格納するバッファへのポインタ。
    \param outputFootSz 出力フッターバッファのサイズが入力され、実際のサイズを返します。

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;
    byte derBuff[] = { }; // DERエンコードされた証明書で初期化
    byte data[] = {}; // 署名するデータで初期化
    byte pkcs7HeadBuff[FOURK_BUF/2];
    byte pkcs7FootBuff[FOURK_BUF/2];
    word32 pkcs7HeadSz = (word32)sizeof(pkcs7HeadBuff);
    word32 pkcs7FootSz = (word32)sizeof(pkcs7HeadBuff);
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
    byte   hashBuf[WC_MAX_DIGEST_SIZE];
    word32 hashSz = wc_HashGetDigestSize(hashType);

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // エンコードするメッセージとデータを更新
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = NULL;
    pkcs7.contentSz = dataSz;
    pkcs7.hashOID = SHAh;
    pkcs7.rng = &rng;
    ... など

    // コンテンツのハッシュを計算
    ret = wc_HashInit(&hash, hashType);
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, hashType, data, sizeof(data));
        if (ret == 0) {
            ret = wc_HashFinal(&hash, hashType, hashBuf);
        }
        wc_HashFree(&hash, hashType);
    }

    ret = wc_PKCS7_EncodeSignedData_ex(&pkcs7, hashBuf, hashSz, pkcs7HeadBuff,
        &pkcs7HeadSz, pkcs7FootBuff, &pkcs7FootSz);
    if ( ret != 0 ) {
        // 出力バッファへのエンコードエラー
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_VerifySignedData_ex
*/
int wc_PKCS7_EncodeSignedData_ex(PKCS7* pkcs7, const byte* hashBuf,
    word32 hashSz, byte* outputHead, word32* outputHeadSz, byte* outputFoot,
    word32* outputFootSz);

/*!
    \ingroup PKCS7

    \brief この関数は、送信されたPKCS7署名付きデータメッセージを受け取り、証明書リストと証明書失効リストを抽出し、署名を検証します。抽出されたコンテンツを与えられたPKCS7構造体に格納します。

    \return 0 メッセージから情報を正常に抽出した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効な場合に返されます。
    \return ASN_PARSE_E 与えられたpkiMsgの解析エラーがある場合に返されます。
    \return PKCS7_OID_E 与えられたpkiMsgが署名付きデータタイプでない場合に返されます。
    \return ASN_VERSION_E PKCS7署名者情報がバージョン1でない場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return PUBLIC_KEY_E 公開鍵の解析エラーがある場合に返されます。
    \return RSA_BUFFER_E バッファエラー、出力が小さすぎるか入力が大きすぎる場合に返されます。
    \return BUFFER_E 指定されたバッファがエンコードされた証明書を保持するのに十分な大きさでない場合に返されます。
    \return MP_INIT_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_READ_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_CMP_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_INVMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_EXPTMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MUL_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_ADD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MULMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_TO_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MEM 署名の生成エラーがある場合に返される可能性があります。

    \param pkcs7 解析された証明書を格納するPKCS7構造体へのポインタ。
    \param pkiMsg 検証およびデコードする署名付きメッセージを含むバッファへのポインタ。
    \param pkiMsgSz 署名付きメッセージのサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;
    byte pkcs7Buff[] = {}; // PKCS7署名

    wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    // エンコードするメッセージとデータを更新
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... など

    ret = wc_PKCS7_VerifySignedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
    	// 出力バッファへのエンコードエラー
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeSignedData
*/
int  wc_PKCS7_VerifySignedData(PKCS7* pkcs7,
                                       byte* pkiMsg, word32 pkiMsgSz);

/*!
    \ingroup PKCS7

    \brief この関数は、ハッシュ/ヘッダー/フッターとして送信されたPKCS7署名付きデータメッセージを受け取り、証明書リストと証明書失効リストを抽出し、署名を検証します。抽出されたコンテンツを与えられたPKCS7構造体に格納します。

    \return 0 メッセージから情報を正常に抽出した場合に返されます。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効な場合に返されます。
    \return ASN_PARSE_E 与えられたpkiMsgの解析エラーがある場合に返されます。
    \return PKCS7_OID_E 与えられたpkiMsgが署名付きデータタイプでない場合に返されます。
    \return ASN_VERSION_E PKCS7署名者情報がバージョン1でない場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return PUBLIC_KEY_E 公開鍵の解析エラーがある場合に返されます。
    \return RSA_BUFFER_E バッファエラー、出力が小さすぎるか入力が大きすぎる場合に返されます。
    \return BUFFER_E 指定されたバッファがエンコードされた証明書を保持するのに十分な大きさでない場合に返されます。
    \return MP_INIT_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_READ_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_CMP_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_INVMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_EXPTMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MUL_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_ADD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MULMOD_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_TO_E 署名の生成エラーがある場合に返される可能性があります。
    \return MP_MEM 署名の生成エラーがある場合に返される可能性があります。

    \param pkcs7 解析された証明書を格納するPKCS7構造体へのポインタ。
    \param hashBuf コンテンツデータの計算されたハッシュへのポインタ。
    \param hashSz ダイジェストのサイズ。
    \param pkiMsgHead 検証およびデコードする署名付きメッセージヘッダーを含むバッファへのポインタ。
    \param pkiMsgHeadSz 署名付きメッセージヘッダーのサイズ。
    \param pkiMsgFoot 検証およびデコードする署名付きメッセージフッターを含むバッファへのポインタ。
    \param pkiMsgFootSz 署名付きメッセージフッターのサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;
    byte data[] = {}; // 署名するデータで初期化
    byte pkcs7HeadBuff[] = {}; // PKCS7ヘッダーで初期化
    byte pkcs7FootBuff[] = {}; // PKCS7フッターで初期化
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
    byte   hashBuf[WC_MAX_DIGEST_SIZE];
    word32 hashSz = wc_HashGetDigestSize(hashType);

    wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    // エンコードするメッセージとデータを更新
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = NULL;
    pkcs7.contentSz = dataSz;
    pkcs7.rng = &rng;
    ... など

    // コンテンツのハッシュを計算
    ret = wc_HashInit(&hash, hashType);
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, hashType, data, sizeof(data));
        if (ret == 0) {
            ret = wc_HashFinal(&hash, hashType, hashBuf);
        }
        wc_HashFree(&hash, hashType);
    }

    ret = wc_PKCS7_VerifySignedData_ex(&pkcs7, hashBuf, hashSz, pkcs7HeadBuff,
        sizeof(pkcs7HeadBuff), pkcs7FootBuff, sizeof(pkcs7FootBuff));
    if ( ret != 0 ) {
        // 出力バッファへのエンコードエラー
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeSignedData_ex
*/
int wc_PKCS7_VerifySignedData_ex(PKCS7* pkcs7, const byte* hashBuf,
    word32 hashSz, byte* pkiMsgHead, word32 pkiMsgHeadSz, byte* pkiMsgFoot,
    word32 pkiMsgFootSz);

/*!
    \ingroup PKCS7

    \brief カスタムAES鍵ラップ/アンラップ操作を実行するために使用されるコールバック関数を設定します。

    \retval 0 コールバック関数が正常に設定されました。
    \retval BAD_FUNC_ARG パラメータpkcs7がNULLです。

    \param pkcs7 PKCS7構造体へのポインタ。
    \param aesKeyWrapCb カスタムAES鍵ラップ/アンラップ関数へのポインタ。
*/
int wc_PKCS7_SetAESKeyWrapUnwrapCb(wc_PKCS7* pkcs7,
        CallbackAESKeyWrapUnwrap aesKeyWrapCb);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7エンベロープデータコンテンツタイプをビルドし、PKCS7構造体を解析可能なPKCS7エンベロープデータパケットを含むバッファにエンコードします。

    \return Success エンベロープデータ形式でメッセージを正常にエンコードした場合、出力バッファに書き込まれたサイズを返します。
    \return BAD_FUNC_ARG: 入力パラメータの1つが無効な場合、またはPKCS7構造体に必要な要素が欠けている場合に返されます。
    \return ALGO_ID_E PKCS7構造体がサポートされていないアルゴリズムタイプを使用している場合に返されます。現在、DesbとDES3bのみがサポートされています。
    \return BUFFER_E 指定された出力バッファが出力データを格納するのに小さすぎる場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return RNG_FAILURE_E 暗号化用の乱数生成器の初期化エラーがある場合に返されます。
    \return DRBG_FAILED 暗号化に使用される乱数生成器で数値の生成エラーがある場合に返されます。
    \return NOT_COMPILED_IN ECC鍵を使用していて、wolfSSLがHAVE_X963_KDFサポートなしでビルドされている場合に返される可能性があります。

    \param pkcs7 エンコードするPKCS7構造体へのポインタ。
    \param output エンコードされた証明書を格納するバッファへのポインタ。
    \param outputSz 出力バッファで利用可能なサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { }; // DERエンコードされた証明書で初期化
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // エンコードするメッセージとデータを更新
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... など

    ret = wc_PKCS7_EncodeEnvelopedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret < 0 ) {
    	// 出力バッファへのエンコードエラー
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_DecodeEnvelopedData
*/
int  wc_PKCS7_EncodeEnvelopedData(PKCS7* pkcs7,
                                          byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7エンベロープデータコンテンツタイプをアンラップして復号し、メッセージをoutputにデコードします。渡されたPKCS7オブジェクトの秘密鍵を使用してメッセージを復号します。

    注意: EnvelopedDataがECC鍵とKeyAgreementRecipientInfo構造体を使用して暗号化されている場合、wolfcrypt組み込みのAES鍵ラップ/アンラップ機能を有効にするためにHAVE_AES_KEYWRAPビルドオプションを有効にするか、wc_PKCS7_SetAESKeyWrapUnwrapCb()を使用してカスタムAES鍵ラップ/アンラップコールバックを設定する必要があります。これらのいずれも該当しない場合、復号は失敗します。

    \return メッセージから情報を正常に抽出した場合、outputに書き込まれたバイト数を返します。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効な場合に返されます。
    \return ASN_PARSE_E 与えられたpkiMsgの解析エラーがある場合に返されます。
    \return PKCS7_OID_E 与えられたpkiMsgがエンベロープデータタイプでない場合に返されます。
    \return ASN_VERSION_E PKCS7署名者情報がバージョン0でない場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return ALGO_ID_E PKCS7構造体がサポートされていないアルゴリズムタイプを使用している場合に返されます。現在、暗号化にはDesbとDES3bのみがサポートされており、署名生成にはRSAkがサポートされています。
    \return PKCS7_RECIP_E エンベロープデータ内に提供された受信者と一致する受信者が見つからない場合に返されます。
    \return RSA_BUFFER_E バッファエラー、出力が小さすぎるか入力が大きすぎることによるRSA署名検証中のエラーがある場合に返されます。
    \return MP_INIT_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_READ_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_CMP_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_INVMOD_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_EXPTMOD_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_MOD_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_MUL_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_ADD_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_MULMOD_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_TO_E 署名検証中にエラーがある場合に返される可能性があります。
    \return MP_MEM 署名検証中にエラーがある場合に返される可能性があります。
    \return NOT_COMPILED_IN EnvelopedDataがECC鍵を使用して暗号化されていて、wolfSSLがHAVE_X963_KDFサポートなしでビルドされている場合に返される可能性があります。

    \param pkcs7 エンベロープデータパッケージをデコードするための秘密鍵を含むPKCS7構造体へのポインタ。
    \param pkiMsg エンベロープデータパッケージを含むバッファへのポインタ。
    \param pkiMsgSz エンベロープデータパッケージのサイズ。
    \param output デコードされたメッセージを格納するバッファへのポインタ。
    \param outputSz 出力バッファで利用可能なサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    byte received[] = { }; // 受信したエンベロープデータメッセージで初期化
    byte decoded[FOURK_BUF];
    int decodedSz;

    // 証明書でpkcs7を初期化
    // 鍵を更新
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;

    decodedSz = wc_PKCS7_DecodeEnvelopedData(&pkcs7, received, sizeof(received),
            decoded, sizeof(decoded));
    if ( decodedSz < 0 ) {
    	// メッセージのデコードエラー
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeEnvelopedData
*/
int  wc_PKCS7_DecodeEnvelopedData(PKCS7* pkcs7, byte* pkiMsg,
        word32 pkiMsgSz, byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief この関数は、KeyAgreeRecipientInfo RecipientInfoオブジェクトを含むEnvelopedDataパッケージからKeyAgreeRecipientIdentifierオブジェクトを抽出します。最初のRecipientInfoで見つかった最初のKeyAgreeRecipientIdentiferのみがコピーされます。この関数は、複数のRecipientInfoオブジェクトやKeyAgreeRecipientInfo内の複数のRecipientEncryptedKeyオブジェクトをサポートしていません。

    \return 成功時に0を返します。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効な場合に返されます。
    \return ASN_PARSE_E 入力メッセージの解析エラーがある場合に返されます。
    \return PKCS7_OID_E 入力メッセージがエンベロープデータタイプでない場合に返されます。
    \return BUFFER_E 出力バッファに十分なスペースがない場合に返されます。

    \param[in] in EnvelopedData ContentInfoメッセージを含む入力バッファ。
    \param[in] inSz 入力バッファのサイズ。
    \param[out] out 出力バッファ。
    \param[in,out] outSz 入力時の出力バッファサイズ、出力時に書き込まれたサイズ。
*/
int wc_PKCS7_GetEnvelopedDataKariRid(const byte * in, word32 inSz,
        byte * out, word32 * outSz);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7暗号化データコンテンツタイプをアンラップして復号し、メッセージをoutputにデコードします。pkcs7->encryptionKeyとpkcs7->encryptionKeySzを介して渡されたPKCS7オブジェクトの暗号化鍵を使用してメッセージを復号します。

    \return メッセージから情報を正常に抽出した場合、outputに書き込まれたバイト数を返します。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効な場合に返されます。
    \return ASN_PARSE_E 与えられたpkiMsgの解析エラーがある場合に返されます。
    \return PKCS7_OID_E 与えられたpkiMsgが暗号化データタイプでない場合に返されます。
    \return ASN_VERSION_E PKCS7署名者情報がバージョン0でない場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return BUFFER_E 暗号化されたコンテンツのサイズが無効な場合に返されます。

    \param pkcs7 暗号化データパッケージをデコードするための暗号化鍵を含むPKCS7構造体へのポインタ。
    \param pkiMsg 暗号化データパッケージを含むバッファへのポインタ。
    \param pkiMsgSz 暗号化データパッケージのサイズ。
    \param output デコードされたメッセージを格納するバッファへのポインタ。
    \param outputSz 出力バッファで利用可能なサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    byte received[] = { }; // 受信した暗号化データメッセージで初期化
    byte decoded[FOURK_BUF];
    int decodedSz;

    // 証明書でpkcs7を初期化
    // 鍵を更新
    pkcs7.encryptionKey = key;
    pkcs7.encryptionKeySz = keySz;

    decodedSz = wc_PKCS7_DecodeEncryptedData(&pkcs7, received,
        sizeof(received), decoded, sizeof(decoded));
    if ( decodedSz < 0 ) {
        // メッセージのデコードエラー
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
int wc_PKCS7_DecodeEncryptedData(PKCS7* pkcs7, byte* pkiMsg,
        word32 pkiMsgSz, byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief この関数は、PKCS7暗号化鍵パッケージコンテンツタイプをアンラップして復号し、メッセージをoutputにデコードします。ラップされたコンテンツタイプがEncryptedDataの場合、pkcs7入力構造体に暗号化鍵を設定する必要があります（pkcs7->encryptionKeyとpkcs7->encryptionKeySzを介して）。ラップされたコンテンツタイプがEnvelopedDataの場合、pkcs7入力構造体に秘密鍵を設定する必要があります（pkcs7->privateKeyとpkcs7->privateKeySzを介して）。
    AuthEnvelopedDataのラップされたコンテンツタイプは現在サポートされていません。

    この関数は、ラップされたコンテンツタイプに応じて、wc_PKCS7_DecodeEnvelopedData()またはwc_PKCS7_DecodeEncryptedData()を自動的に呼び出します。この関数は、ここにリストされているエラーコードに加えて、これらの関数のいずれかからのエラーコードを返す可能性があります。

    \return メッセージから情報を正常に抽出した場合、outputに書き込まれたバイト数を返します。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効な場合に返されます。
    \return ASN_PARSE_E 与えられたpkiMsgの解析エラーがある場合、またはラップされたコンテンツタイプがEncryptedDataで、EncryptedDataのサポートがコンパイルされていない場合（例: NO_PKCS7_ENCRYPTED_DATAが設定されている場合）に返されます。
    \return PKCS7_OID_E 与えられたpkiMsgが暗号化鍵パッケージデータタイプでない場合に返されます。

    \param pkcs7 暗号化鍵パッケージをデコードするための秘密鍵または暗号化鍵を含むPKCS7構造体へのポインタ。
    \param pkiMsg 暗号化鍵パッケージメッセージを含むバッファへのポインタ。
    \param pkiMsgSz 暗号化鍵パッケージメッセージのサイズ。
    \param output デコードされた出力を格納するバッファへのポインタ。
    \param outputSz 出力バッファで利用可能なサイズ。

    _Example_
    \code
    PKCS7 pkcs7;
    byte received[] = { }; // 受信した暗号化データメッセージで初期化
    byte decoded[FOURK_BUF];
    int decodedSz;

    // 証明書でpkcs7を初期化
    // 予想されるEnvelopedDataの鍵を更新（例）
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;

    decodedSz = wc_PKCS7_DecodeEncryptedKeyPackage(&pkcs7, received,
        sizeof(received), decoded, sizeof(decoded));
    if ( decodedSz < 0 ) {
        // メッセージのデコードエラー
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
int wc_PKCS7_DecodeEncryptedKeyPackage(wc_PKCS7 * pkcs7,
        byte * pkiMsg, word32 pkiMsgSz, byte * output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief この関数は、SymmetricKeyPackage属性へのアクセスを提供します。

    \return 0 要求された属性が正常に見つかりました。
    attrとattrSz出力変数には、属性のアドレスとサイズが入力されます。属性は、skp入力ポインタを介して渡されたのと同じバッファ内にあります。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効です。
    \return ASN_PARSE_E 入力オブジェクトの解析中にエラーが発生しました。
    \return BAD_INDEX_E 要求された属性インデックスが無効でした。

    \param[in] skp SymmetricKeyPackageオブジェクトを含む入力バッファ。
    \param[in] skpSz SymmetricKeyPackageオブジェクトのサイズ。
    \param[in] index アクセスする属性のインデックス。
    \param[out] attr 要求された属性オブジェクトへのポインタを格納するバッファ。
    \param[out] attrSz 要求された属性オブジェクトのサイズを格納するバッファ。
*/
int wc_PKCS7_DecodeSymmetricKeyPackageAttribute(const byte * skp,
        word32 skpSz, size_t index, const byte ** attr, word32 * attrSz);

/*!
    \ingroup PKCS7

    \brief この関数は、SymmetricKeyPackage鍵へのアクセスを提供します。

    \return 0 要求された鍵が正常に見つかりました。
    keyとkeySz出力変数には、鍵のアドレスとサイズが入力されます。鍵は、skp入力ポインタを介して渡されたのと同じバッファ内にあります。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効です。
    \return ASN_PARSE_E 入力オブジェクトの解析中にエラーが発生しました。
    \return BAD_INDEX_E 要求された鍵インデックスが無効でした。

    \param[in] skp SymmetricKeyPackageオブジェクトを含む入力バッファ。
    \param[in] skpSz SymmetricKeyPackageオブジェクトのサイズ。
    \param[in] index アクセスする鍵のインデックス。
    \param[out] key 要求された鍵オブジェクトへのポインタを格納するバッファ。
    \param[out] keySz 要求された鍵オブジェクトのサイズを格納するバッファ。
*/
int wc_PKCS7_DecodeSymmetricKeyPackageKey(const byte * skp,
        word32 skpSz, size_t index, const byte ** key, word32 * keySz);

/*!
    \ingroup PKCS7

    \brief この関数は、OneSymmetricKey属性へのアクセスを提供します。

    \return 0 要求された属性が正常に見つかりました。
    attrとattrSz出力変数には、属性のアドレスとサイズが入力されます。属性は、osk入力ポインタを介して渡されたのと同じバッファ内にあります。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効です。
    \return ASN_PARSE_E 入力オブジェクトの解析中にエラーが発生しました。
    \return BAD_INDEX_E 要求された属性インデックスが無効でした。

    \param[in] osk OneSymmetricKeyオブジェクトを含む入力バッファ。
    \param[in] oskSz OneSymmetricKeyオブジェクトのサイズ。
    \param[in] index アクセスする属性のインデックス。
    \param[out] attr 要求された属性オブジェクトへのポインタを格納するバッファ。
    \param[out] attrSz 要求された属性オブジェクトのサイズを格納するバッファ。
*/
int wc_PKCS7_DecodeOneSymmetricKeyAttribute(const byte * osk,
        word32 oskSz, size_t index, const byte ** attr, word32 * attrSz);

/*!
    \ingroup PKCS7

    \brief この関数は、OneSymmetricKey鍵へのアクセスを提供します。

    \return 0 要求された鍵が正常に見つかりました。
    keyとkeySz出力変数には、鍵のアドレスとサイズが入力されます。鍵は、osk入力ポインタを介して渡されたのと同じバッファ内にあります。
    \return BAD_FUNC_ARG 入力パラメータの1つが無効です。
    \return ASN_PARSE_E 入力オブジェクトの解析中にエラーが発生しました。

    \param[in] osk OneSymmetricKeyオブジェクトを含む入力バッファ。
    \param[in] oskSz OneSymmetricKeyオブジェクトのサイズ。
    \param[out] key 要求された鍵オブジェクトへのポインタを格納するバッファ。
    \param[out] keySz 要求された鍵オブジェクトのサイズを格納するバッファ。
*/
int wc_PKCS7_DecodeOneSymmetricKeyKey(const byte * osk,
        word32 oskSz, const byte ** key, word32 * keySz);