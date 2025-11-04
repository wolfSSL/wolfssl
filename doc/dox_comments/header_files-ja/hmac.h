/*!
    \ingroup HMAC

    \brief この関数はHmacオブジェクトを初期化し、暗号化タイプ、鍵、およびHMAC長を設定します。

    \return 0 Hmacオブジェクトの初期化に成功した場合に返されます。
    \return BAD_FUNC_ARG 入力タイプが無効な場合に返されます（typeパラメータを参照）。
    \return MEMORY_E ハッシュに使用する構造体のメモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準の14バイトより短い場合に返されます。

    \param hmac 初期化するHmacオブジェクトへのポインタ。
    \param type Hmacオブジェクトが使用する暗号化方式を指定するタイプ。有効なオプションは：WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512。
    \param key Hmacオブジェクトを初期化する鍵を含むバッファへのポインタ。
    \param length 鍵の長さ。

    _Example_
    \code
    Hmac hmac;
    byte key[] = { // 暗号化に使用する鍵で初期化 };
    if (wc_HmacSetKey(&hmac, WC_MD5, key, sizeof(key)) != 0) {
    	// Hmacオブジェクトの初期化エラー
    }
    \endcode

    \sa wc_HmacUpdate
    \sa wc_HmacFinal
*/
int wc_HmacSetKey(Hmac* hmac, int type, const byte* key, word32 keySz);

/*!
    \ingroup HMAC

    \brief この関数は、HMACを使用して認証するメッセージを更新します。wc_HmacSetKeyでHmacオブジェクトが初期化された後に呼び出す必要があります。この関数は、ハッシュするメッセージを更新するために複数回呼び出すことができます。必要に応じてwc_HmacUpdateを呼び出した後、wc_HmacFinalを呼び出して最終的な認証メッセージタグを取得する必要があります。

    \return 0 認証するメッセージの更新に成功した場合に返されます。
    \return MEMORY_E ハッシュアルゴリズムで使用するメモリ割り当てエラーがある場合に返されます。

    \param hmac メッセージを更新するHmacオブジェクトへのポインタ。
    \param msg 追加するメッセージを含むバッファへのポインタ。
    \param length 追加するメッセージの長さ。

    _Example_
    \code
    Hmac hmac;
    byte msg[] = { // 認証するメッセージで初期化 };
    byte msg2[] = { // メッセージの後半で初期化 };
    // hmacを初期化
    if( wc_HmacUpdate(&hmac, msg, sizeof(msg)) != 0) {
    	// メッセージ更新エラー
    }
    if( wc_HmacUpdate(&hmac, msg2, sizeof(msg)) != 0) {
    	// 2番目のメッセージでの更新エラー
    }
    \endcode

    \sa wc_HmacSetKey
    \sa wc_HmacFinal
*/
int wc_HmacUpdate(Hmac* hmac, const byte* in, word32 sz);

/*!
    \ingroup HMAC

    \brief この関数は、Hmacオブジェクトのメッセージの最終ハッシュを計算します。

    \return 0 最終ハッシュの計算に成功した場合に返されます。
    \return MEMORY_E ハッシュアルゴリズムで使用するメモリ割り当てエラーがある場合に返されます。

    \param hmac 最終ハッシュを計算するHmacオブジェクトへのポインタ。
    \param hash 最終ハッシュを保存するバッファへのポインタ。選択したハッシュアルゴリズムに必要なスペースを確保する必要があります。

    _Example_
    \code
    Hmac hmac;
    byte hash[MD5_DIGEST_SIZE];
    // タイプとしてMD5でhmacを初期化
    // メッセージでwc_HmacUpdate()

    if (wc_HmacFinal(&hmac, hash) != 0) {
    	// ハッシュ計算エラー
    }
    \endcode

    \sa wc_HmacSetKey
    \sa wc_HmacUpdate
*/
int wc_HmacFinal(Hmac* hmac, byte* out);

/*!
    \ingroup HMAC

    \brief この関数は、設定された暗号スイートに基づいて利用可能な最大のHMACダイジェストサイズを返します。

    \return Success 設定された暗号スイートに基づいて利用可能な最大のHMACダイジェストサイズを返します。

    \param none パラメータなし。

    _Example_
    \code
    int maxDigestSz = wolfSSL_GetHmacMaxSize();
    \endcode

    \sa none
*/
int wolfSSL_GetHmacMaxSize(void);

/*!
    \ingroup HMAC

    \brief この関数は、HMAC鍵導出関数（HKDF）へのアクセスを提供します。HMACを利用して、オプションのソルトとオプションの情報を含むinKeyを導出鍵に変換し、outに保存します。ハッシュタイプは、0またはNULLが指定された場合、デフォルトでMD5になります。

    HMAC設定オプションは--enable-hmac（デフォルトでオン）、またはソースを直接ビルドする場合はHAVE_HKDFです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param type HKDFに使用するハッシュタイプ。有効なタイプは：WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512。
    \param inKey KDFに使用する鍵を含むバッファへのポインタ。
    \param inKeySz 入力鍵の長さ。
    \param salt オプションのソルトを含むバッファへのポインタ。ソルトを使用しない場合はNULLを使用します。
    \param saltSz ソルトの長さ。ソルトを使用しない場合は0を使用します。
    \param info オプションの追加情報を含むバッファへのポインタ。追加情報を追加しない場合はNULLを使用します。
    \param infoSz 追加情報の長さ。追加情報を使用しない場合は0を使用します。
    \param out 導出鍵を保存するバッファへのポインタ。
    \param outSz 生成された鍵を保存する出力バッファで利用可能なスペース。

    _Example_
    \code
    byte key[] = { // 鍵で初期化 };
    byte salt[] = { // ソルトで初期化 };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF(WC_SHA512, key, sizeof(key), salt, sizeof(salt),
    NULL, 0, derivedKey, sizeof(derivedKey));
    if ( ret != 0 ) {
	    // 導出鍵の生成エラー
    }
    \endcode

    \sa wc_HmacSetKey
*/
int wc_HKDF(int type, const byte* inKey, word32 inKeySz,
                    const byte* salt, word32 saltSz,
                    const byte* info, word32 infoSz,
                    byte* out, word32 outSz);


/*!
    \ingroup HMAC

    \brief この関数は、HMAC鍵導出関数（HKDF）へのアクセスを提供します。HMACを利用して、オプションのソルトを含むinKeyを導出鍵に変換し、outに保存します。ハッシュタイプは、0またはNULLが指定された場合、デフォルトでMD5になります。

    HMAC設定オプションは--enable-hmac（デフォルトでオン）、またはソースを直接ビルドする場合はHAVE_HKDFです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param type HKDFに使用するハッシュタイプ。有効なタイプは：WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512。
    \param salt オプションのソルトを含むバッファへのポインタ。ソルトを使用しない場合はNULLを使用します。
    \param saltSz ソルトの長さ。ソルトを使用しない場合は0を使用します。
    \param inKey KDFに使用する鍵を含むバッファへのポインタ。
    \param inKeySz 入力鍵の長さ。
    \param out 導出鍵を保存するバッファへのポインタ。

    _Example_
    \code
    byte key[] = { // 鍵で初期化 };
    byte salt[] = { // ソルトで初期化 };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Extract(WC_SHA512, salt, sizeof(salt), key, sizeof(key),
        derivedKey);
    if ( ret != 0 ) {
	    // 導出鍵の生成エラー
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_HKDF_Expand_ex
*/
int wc_HKDF_Extract(
    int type,
    const byte* salt, word32 saltSz,
    const byte* inKey, word32 inKeySz,
    byte* out);

/*!
    \ingroup HMAC

    \brief この関数は、HMAC鍵導出関数（HKDF）へのアクセスを提供します。HMACを利用して、オプションのソルトを含むinKeyを導出鍵に変換し、outに保存します。ハッシュタイプは、0またはNULLが指定された場合、デフォルトでMD5になります。これは、ヒープヒントとデバイス識別子を追加する_exバージョンです。

    HMAC設定オプションは--enable-hmac（デフォルトでオン）、またはソースを直接ビルドする場合はHAVE_HKDFです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param type HKDFに使用するハッシュタイプ。有効なタイプは：WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512。
    \param salt オプションのソルトを含むバッファへのポインタ。ソルトを使用しない場合はNULLを使用します。
    \param saltSz ソルトの長さ。ソルトを使用しない場合は0を使用します。
    \param inKey KDFに使用する鍵を含むバッファへのポインタ。
    \param inKeySz 入力鍵の長さ。
    \param out 導出鍵を保存するバッファへのポインタ。
    \param heap メモリに使用するヒープヒント。NULLにできます。
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定します。

    _Example_
    \code
    byte key[] = { // 鍵で初期化 };
    byte salt[] = { // ソルトで初期化 };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Extract_ex(WC_SHA512, salt, sizeof(salt), key, sizeof(key),
        derivedKey, NULL, INVALID_DEVID);
    if ( ret != 0 ) {
	    // 導出鍵の生成エラー
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Expand
    \sa wc_HKDF_Expand_ex
*/
int wc_HKDF_Extract_ex(
    int type,
    const byte* salt, word32 saltSz,
    const byte* inKey, word32 inKeySz,
    byte* out,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief この関数は、HMAC鍵導出関数（HKDF）へのアクセスを提供します。HMACを利用して、オプションの情報を含むinKeyを導出鍵に変換し、outに保存します。ハッシュタイプは、0またはNULLが指定された場合、デフォルトでMD5になります。

    HMAC設定オプションは--enable-hmac（デフォルトでオン）、またはソースを直接ビルドする場合はHAVE_HKDFです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param type HKDFに使用するハッシュタイプ。有効なタイプは：WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512。
    \param inKey KDFに使用する鍵を含むバッファへのポインタ。
    \param inKeySz 入力鍵の長さ。
    \param info オプションの追加情報を含むバッファへのポインタ。追加情報を追加しない場合はNULLを使用します。
    \param infoSz 追加情報の長さ。追加情報を使用しない場合は0を使用します。
    \param out 導出鍵を保存するバッファへのポインタ。
    \param outSz 生成された鍵を保存する出力バッファで利用可能なスペース。

    _Example_
    \code
    byte key[] = { // 鍵で初期化 };
    byte salt[] = { // ソルトで初期化 };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Expand(WC_SHA512, key, sizeof(key), NULL, 0,
        derivedKey, sizeof(derivedKey));
    if ( ret != 0 ) {
	    // 導出鍵の生成エラー
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand_ex
*/
int wc_HKDF_Expand(
    int type,
    const byte* inKey, word32 inKeySz,
    const byte* info, word32 infoSz,
    byte* out, word32 outSz);

/*!
    \ingroup HMAC

    \brief この関数は、HMAC鍵導出関数（HKDF）へのアクセスを提供します。HMACを利用して、オプションの情報を含むinKeyを導出鍵に変換し、outに保存します。ハッシュタイプは、0またはNULLが指定された場合、デフォルトでMD5になります。これは、ヒープヒントとデバイス識別子を追加する_exバージョンです。

    HMAC設定オプションは--enable-hmac（デフォルトでオン）、またはソースを直接ビルドする場合はHAVE_HKDFです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param type HKDFに使用するハッシュタイプ。有効なタイプは：WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512。
    \param inKey KDFに使用する鍵を含むバッファへのポインタ。
    \param inKeySz 入力鍵の長さ。
    \param info オプションの追加情報を含むバッファへのポインタ。追加情報を追加しない場合はNULLを使用します。
    \param infoSz 追加情報の長さ。追加情報を使用しない場合は0を使用します。
    \param out 導出鍵を保存するバッファへのポインタ。
    \param outSz 生成された鍵を保存する出力バッファで利用可能なスペース。
    \param heap メモリに使用するヒープヒント。NULLにできます。
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定します。

    _Example_
    \code
    byte key[] = { // 鍵で初期化 };
    byte salt[] = { // ソルトで初期化 };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Expand_ex(WC_SHA512, key, sizeof(key), NULL, 0,
        derivedKey, sizeof(derivedKey), NULL, INVALID_DEVID);
    if ( ret != 0 ) {
	    // 導出鍵の生成エラー
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
*/
int wc_HKDF_Expand_ex(
    int type,
    const byte* inKey, word32 inKeySz,
    const byte* info, word32 infoSz,
    byte* out, word32 outSz,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief この関数は、TLS v1.3鍵導出のためのRFC 5869 HMACベース抽出拡張鍵導出関数（HKDF）へのアクセスを提供します。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param prk 生成された疑似ランダム鍵。
    \param salt ソルト。
    \param saltLen ソルトの長さ。
    \param ikm 鍵材料の出力へのポインタ。
    \param ikmLen 入力鍵材料バッファの長さ。
    \param digest HKDFに使用するハッシュタイプ。有効なタイプは：WC_SHA256、WC_SHA384、またはWC_SHA512。

    _Example_
    \code
    byte secret[] = { // ランダム鍵で初期化 };
    byte salt[] = { // オプションのソルトで初期化 };
    byte masterSecret[MAX_DIGEST_SIZE];

    int ret = wc_Tls13_HKDF_Extract(secret, salt, sizeof(salt), 0,
        masterSecret, sizeof(masterSecret), WC_SHA512);
    if ( ret != 0 ) {
	    // 導出鍵の生成エラー
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Extract_ex
*/
int wc_Tls13_HKDF_Extract(
    byte* prk,
    const byte* salt, word32 saltLen,
    byte* ikm, word32 ikmLen, int digest);

/*!
    \ingroup HMAC

    \brief この関数は、TLS v1.3鍵導出のためのRFC 5869 HMACベース抽出拡張鍵導出関数（HKDF）へのアクセスを提供します。これは、ヒープヒントとデバイス識別子を追加する_exバージョンです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param prk 生成された疑似ランダム鍵。
    \param salt ソルト。
    \param saltLen ソルトの長さ。
    \param ikm 鍵材料の出力へのポインタ。
    \param ikmLen 入力鍵材料バッファの長さ。
    \param digest HKDFに使用するハッシュタイプ。有効なタイプは：WC_SHA256、WC_SHA384、またはWC_SHA512。
    \param heap メモリに使用するヒープヒント。NULLにできます。
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定します。

    _Example_
    \code
    byte secret[] = { // ランダム鍵で初期化 };
    byte salt[] = { // オプションのソルトで初期化 };
    byte masterSecret[MAX_DIGEST_SIZE];

    int ret = wc_Tls13_HKDF_Extract_ex(secret, salt, sizeof(salt), 0,
        masterSecret, sizeof(masterSecret), WC_SHA512, NULL, INVALID_DEVID);
    if ( ret != 0 ) {
	    // 導出鍵の生成エラー
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Extract
*/
int wc_Tls13_HKDF_Extract_ex(
    byte* prk,
    const byte* salt, word32 saltLen,
    byte* ikm, word32 ikmLen, int digest,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief HMAC、ソルト、ラベル、および情報を使用してデータを拡張します。TLS v1.3は鍵導出のためにこの関数を定義しています。これは、ヒープヒントとデバイス識別子を追加する_exバージョンです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param okm 生成された疑似ランダム鍵 - 出力鍵材料。
    \param okmLen 生成された疑似ランダム鍵の長さ - 出力鍵材料。
    \param prk ソルト - 疑似ランダム鍵。
    \param prkLen ソルトの長さ - 疑似ランダム鍵。
    \param protocol TLSプロトコルラベル。
    \param protocolLen TLSプロトコルラベルの長さ。
    \param info 拡張する情報。
    \param infoLen 情報の長さ。
    \param digest HKDFに使用するハッシュタイプ。有効なタイプは：WC_SHA256、WC_SHA384、またはWC_SHA512。
    \param heap メモリに使用するヒープヒント。NULLにできます。
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定します。

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Expand_Label
    \sa wc_Tls13_HKDF_Expand_Label_Alloc
*/
int wc_Tls13_HKDF_Expand_Label_ex(
    byte* okm, word32 okmLen,
    const byte* prk, word32 prkLen,
    const byte* protocol, word32 protocolLen,
    const byte* label, word32 labelLen,
    const byte* info, word32 infoLen,
    int digest,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief HMAC、ソルト、ラベル、および情報を使用してデータを拡張します。TLS v1.3は鍵導出のためにこの関数を定義しています。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param okm 生成された疑似ランダム鍵 - 出力鍵材料。
    \param okmLen 生成された疑似ランダム鍵の長さ - 出力鍵材料。
    \param prk ソルト - 疑似ランダム鍵。
    \param prkLen ソルトの長さ - 疑似ランダム鍵。
    \param protocol TLSプロトコルラベル。
    \param protocolLen TLSプロトコルラベルの長さ。
    \param info 拡張する情報。
    \param infoLen 情報の長さ。
    \param digest HKDFに使用するハッシュタイプ。有効なタイプは：WC_SHA256、WC_SHA384、またはWC_SHA512。

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Expand_Label_ex
    \sa wc_Tls13_HKDF_Expand_Label_Alloc
*/
int wc_Tls13_HKDF_Expand_Label(
    byte* okm, word32 okmLen,
    const byte* prk, word32 prkLen,
    const byte* protocol, word32 protocolLen,
    const byte* label, word32 labelLen,
    const byte* info, word32 infoLen,
    int digest);

/*!
    \ingroup HMAC

    \brief この関数はwc_Tls13_HKDF_Expand_Label()と非常に似ていますが、通常使用されるスタックスペースが十分でない場合にメモリを割り当てます。HMAC、ソルト、ラベル、および情報を使用してデータを拡張します。TLS v1.3は鍵導出のためにこの関数を定義しています。これは、ヒープヒントとデバイス識別子を追加する_exバージョンです。

    \return 0 指定された入力で鍵の生成に成功した場合に返されます。
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合に返されます（typeパラメータを参照）。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return HMAC_MIN_KEYLEN_E FIPS実装を使用していて、指定された鍵の長さが最小許容FIPS標準より短い場合に返される可能性があります。

    \param okm 生成された疑似ランダム鍵 - 出力鍵材料。
    \param okmLen 生成された疑似ランダム鍵の長さ - 出力鍵材料。
    \param prk ソルト - 疑似ランダム鍵。
    \param prkLen ソルトの長さ - 疑似ランダム鍵。
    \param protocol TLSプロトコルラベル。
    \param protocolLen TLSプロトコルラベルの長さ。
    \param info 拡張する情報。
    \param infoLen 情報の長さ。
    \param digest HKDFに使用するハッシュタイプ。有効なタイプは：WC_SHA256、WC_SHA384、またはWC_SHA512。
    \param heap メモリに使用するヒープヒント。NULLにできます。

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Expand_Label
    \sa wc_Tls13_HKDF_Expand_Label_ex
*/
int wc_Tls13_HKDF_Expand_Label_Alloc(
    byte* okm, word32 okmLen,
    const byte* prk, word32 prkLen,
    const byte* protocol, word32 protocolLen,
    const byte* label, word32 labelLen,
    const byte* info, word32 infoLen,
    int digest, void* heap);