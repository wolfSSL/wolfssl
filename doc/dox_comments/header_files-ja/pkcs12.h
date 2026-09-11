/*!
    \ingroup PKCS12

    \brief この関数は、空のWC_PKCS12構造体を新たに作成します。動的メモリにはデフォルトのヒープヒントを使用します。wc_PKCS12_new_ex()にNULLのヒープを渡して呼び出すことと同等です。返された構造体はwc_PKCS12_free()で解放する必要があります。

    \return pointer 成功時に、新たに割り当てられたWC_PKCS12構造体へのポインタを返します。
    \return NULL メモリ割り当てに失敗した場合に返されます。

    \param none パラメータはありません。

    _Example_
    \code
    WC_PKCS12* pkcs12 = wc_PKCS12_new();
    if (pkcs12 == NULL) {
        // PKCS12構造体の割り当てエラー
    }

    // PKCS12構造体を使用する

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_new_ex
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_new(void);

/*!
    \ingroup PKCS12

    \brief この関数は、指定されたヒープヒントを関連付けて、空のWC_PKCS12構造体を新たに作成します。ヒープヒントは構造体に保存され、このWC_PKCS12オブジェクトのために行われる以降のすべての動的な割り当てと解放に使用されます。返された構造体はwc_PKCS12_free()で解放する必要があります。

    \return pointer 成功時に、新たに割り当てられたWC_PKCS12構造体へのポインタを返します。
    \return NULL メモリ割り当てに失敗した場合に返されます。

    \param heap 動的メモリ割り当てに使用するヒープヒントへのポインタ。デフォルトを使用する場合はNULLを指定します。

    _Example_
    \code
    void* heap = NULL; // またはカスタム静的メモリのヒープヒント
    WC_PKCS12* pkcs12 = wc_PKCS12_new_ex(heap);
    if (pkcs12 == NULL) {
        // PKCS12構造体の割り当てエラー
    }

    // PKCS12構造体を使用する

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_new
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_new_ex(void* heap);

/*!
    \ingroup PKCS12

    \brief この関数は、WC_PKCS12構造体と、解析済みのAuthenticated SafeやMACデータを含む、それに関連するすべてのメモリを解放します。NULLを渡しても安全で、その場合は何も行いません。

    \return none 戻り値はありません。

    \param pkcs12 解放するWC_PKCS12構造体へのポインタ。

    _Example_
    \code
    WC_PKCS12* pkcs12 = wc_PKCS12_new();

    // PKCS12構造体を初期化して使用する

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_new
    \sa wc_PKCS12_new_ex
*/
void wc_PKCS12_free(WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12

    \brief この関数は、DERエンコードされたPKCS #12（PFX）バッファをWC_PKCS12構造体に変換します。各ContentInfoの内容は完全に解析またはデコードされることなく、そのままの形で構造体に格納されます。バンドルを復号して秘密鍵と証明書を取り出すには、この後にwc_PKCS12_parse()を呼び出してください。

    \return 0 PKCS #12バッファのデコードに成功した場合に返されます。
    \return BAD_FUNC_ARG derまたはpkcs12がNULLの場合に返されます。
    \return ASN_PARSE_E PKCS #12構造の解析エラーがある場合に返されます。
    \return ASN_VERSION_E バンドル内のバージョンがサポートされていない場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。

    \param der DERエンコードされたPKCS #12バンドルを保持するバッファへのポインタ。
    \param derSz DERバッファのサイズ。
    \param pkcs12 デコードされたバンドルを格納する、割り当て済みのWC_PKCS12構造体へのポインタ。

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte der[] = { }; // DERエンコードされたPKCS #12バンドルで初期化
    word32 derSz = sizeof(der);

    pkcs12 = wc_PKCS12_new();
    if (pkcs12 == NULL) {
        // PKCS12構造体の割り当てエラー
    }

    if (wc_d2i_PKCS12(der, derSz, pkcs12) != 0) {
        // PKCS12バンドルのデコードエラー
    }

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_d2i_PKCS12_fp
    \sa wc_i2d_PKCS12
    \sa wc_PKCS12_parse
*/
int wc_d2i_PKCS12(const byte* der, word32 derSz, WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12

    \brief この関数は、DERエンコードされたPKCS #12（PFX）ファイルをファイルシステムから読み込み、WC_PKCS12構造体にデコードします。`*pkcs12`がNULLの場合、WC_PKCS12構造体が呼び出し元のために新たに割り当てられ、pkcs12引数を通じて返されます。この場合、デコードに失敗するとその構造体は自動的に解放されます。いずれの場合も、正常に返された構造体は呼び出し元がwc_PKCS12_free()で解放する必要があります。この関数はNO_FILESYSTEMが定義されている場合は使用できません。

    \return 0 ファイルの読み込みとデコードに成功した場合に返されます。
    \return BAD_FUNC_ARG pkcs12がNULLの場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return BAD_PATH_ERROR ファイルを開けないか読み込めない場合に返されます。

    \param file 読み込むDERエンコードされたPKCS #12ファイルのパス。
    \param pkcs12 WC_PKCS12ポインタへのポインタ。`*pkcs12`がNULLの場合、新しい構造体が割り当てられてここに返されます。NULLでない場合は既存の構造体が使用されます。

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;

    // wc_d2i_PKCS12_fpに構造体を割り当てさせる
    if (wc_d2i_PKCS12_fp("./certs/test-servercert.p12", &pkcs12) != 0) {
        // PKCS12ファイルの読み込みまたはデコードのエラー
    }

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_d2i_PKCS12
    \sa wc_i2d_PKCS12
    \sa wc_PKCS12_parse
*/
int wc_d2i_PKCS12_fp(const char* file, WC_PKCS12** pkcs12);

/*!
    \ingroup PKCS12

    \brief この関数は、WC_PKCS12構造体をDERエンコードされたPKCS #12（PFX）バッファにエンコードします。der引数とderSz引数によって選択される3つの動作モードがあります。derにNULLを渡した場合は必要なバッファサイズの問い合わせのみを行い、サイズが`*derSz`に格納され、LENGTH_ONLY_Eが返されます。データは書き込まれません。derがNULLでなく`*der`がNULLの場合は必要なサイズのバッファを割り当て、そのアドレスを`*der`に格納します。呼び出し元はDYNAMIC_TYPE_PKCSを指定したXFREE()で解放する必要があります。derがNULLでなく`*der`が呼び出し元の用意したバッファを指している場合は、そのバッファにDERを書き込みます。derSzがNULLでなく、バッファが小さすぎることを示している場合はBUFFER_Eを返します。この最後のケースでは、成功時に`*der`が通常のi2dの慣例に従ってエンコードされたDERの末尾の次のバイトへ進められるため、呼び出し元は元のポインタを別途保持しておく必要があります。

    \return Success 成功時に、DERエンコーディングのサイズをバイト単位で返します。
    \return LENGTH_ONLY_E derがNULLの場合に返され、必要なサイズのみが計算されて`*derSz`に格納されたことを示します。
    \return BAD_FUNC_ARG pkcs12がNULLの場合、構造体がAuthenticated Safeを保持していない場合、またはderとderSzの両方がNULLの場合に返されます。
    \return BUFFER_E 呼び出し元が用意したバッファがエンコーディングを格納するには小さすぎる場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。

    \param pkcs12 エンコードするWC_PKCS12構造体へのポインタ。
    \param der エンコーディングを格納するバッファポインタへのポインタ。必要なサイズを問い合わせる場合はNULLを指定します。
    \param derSz サイズ問い合わせ時には必要なサイズを受け取ります。呼び出し元が用意したバッファを使用する場合は、入力としてそのバッファのサイズを保持します。NULLを指定するとバッファサイズのチェックが無効になります。

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* der = NULL;
    int derSz = 0;

    // pkcs12はwc_PKCS12_createで作成済み、またはwc_d2i_PKCS12でデコード済みとする

    // 必要なサイズを問い合わせる
    if (wc_i2d_PKCS12(pkcs12, NULL, &derSz) != LENGTH_ONLY_E) {
        // エンコードサイズの取得エラー
    }

    // wc_i2d_PKCS12にバッファを割り当てさせる
    if (wc_i2d_PKCS12(pkcs12, &der, NULL) <= 0) {
        // PKCS12バンドルのエンコードエラー
    }

    XFREE(der, NULL, DYNAMIC_TYPE_PKCS);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_d2i_PKCS12
    \sa wc_PKCS12_create
*/
int wc_i2d_PKCS12(WC_PKCS12* pkcs12, byte** der, int* derSz);

/*!
    \ingroup PKCS12

    \brief この関数は、事前にwc_d2i_PKCS12()またはwc_d2i_PKCS12_fp()によって内容が設定されたWC_PKCS12構造体を解析してデコードします。指定されたパスワードでバンドルのMACを検証し、内容を復号して、秘密鍵、エンドエンティティ証明書、および任意でCA証明書チェーンを呼び出し元に返します。鍵と証明書は新たに割り当てられたバッファで返され、呼び出し元が解放する責任を負います。鍵にはXFREE(pkey, heap, DYNAMIC_TYPE_PUBLIC_KEY)を、証明書にはXFREE(cert, heap, DYNAMIC_TYPE_PKCS)を使用してください。ここでheapはWC_PKCS12構造体に関連付けられたヒープヒントです。CAリストを要求した場合は、wc_FreeCertList()で解放する必要があります。秘密鍵はPKCS #8ヘッダーが取り除かれた状態で返されます。PKCS #8ヘッダーを残したい場合はwc_PKCS12_parse_ex()を使用してください。

    \note USER_RSAが有効な場合、RSA鍵ペアを使用していると、返された鍵と対にならない証明書が返される可能性があります。

    \return 0 PKCS #12バンドルの解析に成功した場合に返されます。
    \return BAD_FUNC_ARG pkcs12、psw、pkey、pkeySz、certまたはcertSzがNULLの場合に返されます。
    \return MAC_CMP_FAILED_E MACの検証に失敗した場合に返されます。通常はパスワードが正しくないことを意味します。
    \return ASN_PARSE_E 内容の解析エラーがある場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return UNICODE_SIZE_E 鍵導出に必要なUnicode形式にパスワードを変換できない場合に返されます。

    \param pkcs12 デコード済みのバンドルを保持するWC_PKCS12構造体へのポインタ。
    \param psw MACの検証とバンドルの復号に使用するNULL終端のパスワード。
    \param[out] pkey DERエンコードされた秘密鍵を保持する、新たに割り当てられたバッファを受け取ります。
    \param[out] pkeySz 秘密鍵バッファのサイズを受け取ります。
    \param[out] cert DERエンコードされた証明書を保持する、新たに割り当てられたバッファを受け取ります。
    \param[out] certSz 証明書バッファのサイズを受け取ります。
    \param[out] ca 任意。NULLでない場合、バンドル内で見つかった残りのDERエンコード証明書のリンクリストを受け取ります。wc_FreeCertList()で解放してください。

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* key = NULL;
    byte* cert = NULL;
    WC_DerCertList* ca = NULL;
    word32 keySz = 0;
    word32 certSz = 0;

    if (wc_d2i_PKCS12_fp("./certs/test-servercert.p12", &pkcs12) != 0) {
        // PKCS12ファイルの読み込みエラー
    }

    if (wc_PKCS12_parse(pkcs12, "password", &key, &keySz, &cert, &certSz,
                        &ca) != 0) {
        // バンドルの解析エラー（パスワード誤りなど）
    }

    // 鍵、証明書、CAチェーンを使用する

    XFREE(key, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(cert, NULL, DYNAMIC_TYPE_PKCS);
    wc_FreeCertList(ca, NULL);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_parse_ex
    \sa wc_d2i_PKCS12
    \sa wc_FreeCertList
*/
int wc_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
        byte** pkey, word32* pkeySz, byte** cert, word32* certSz,
        WC_DerCertList** ca);

/*!
    \ingroup PKCS12

    \brief この関数はwc_PKCS12_parse()とまったく同じ動作をしますが、返される秘密鍵にPKCS #8ヘッダーを残すかどうかを制御するkeepKeyHeader引数が追加されています。wc_PKCS12_parse()を呼び出すことは、この関数をkeepKeyHeaderに0を指定して呼び出すことと同等です。所有権の規則もwc_PKCS12_parse()と同じです。鍵はXFREE(pkey, heap, DYNAMIC_TYPE_PUBLIC_KEY)で、証明書はXFREE(cert, heap, DYNAMIC_TYPE_PKCS)で、CAリストはwc_FreeCertList()で解放してください。

    \note USER_RSAが有効な場合、RSA鍵ペアを使用していると、返された鍵と対にならない証明書が返される可能性があります。

    \return 0 PKCS #12バンドルの解析に成功した場合に返されます。
    \return BAD_FUNC_ARG pkcs12、psw、pkey、pkeySz、certまたはcertSzがNULLの場合に返されます。
    \return MAC_CMP_FAILED_E MACの検証に失敗した場合に返されます。通常はパスワードが正しくないことを意味します。
    \return ASN_PARSE_E 内容の解析エラーがある場合に返されます。
    \return MEMORY_E メモリ割り当てエラーがある場合に返されます。
    \return UNICODE_SIZE_E 鍵導出に必要なUnicode形式にパスワードを変換できない場合に返されます。

    \param pkcs12 デコード済みのバンドルを保持するWC_PKCS12構造体へのポインタ。
    \param psw MACの検証とバンドルの復号に使用するNULL終端のパスワード。
    \param[out] pkey DERエンコードされた秘密鍵を保持する、新たに割り当てられたバッファを受け取ります。
    \param[out] pkeySz 秘密鍵バッファのサイズを受け取ります。
    \param[out] cert DERエンコードされた証明書を保持する、新たに割り当てられたバッファを受け取ります。
    \param[out] certSz 証明書バッファのサイズを受け取ります。
    \param[out] ca 任意。NULLでない場合、バンドル内で見つかった残りのDERエンコード証明書のリンクリストを受け取ります。wc_FreeCertList()で解放してください。
    \param keepKeyHeader 返される鍵からPKCS #8ヘッダーを取り除く場合は0、残す場合は0以外を指定します。

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* key = NULL;
    byte* cert = NULL;
    WC_DerCertList* ca = NULL;
    word32 keySz = 0;
    word32 certSz = 0;

    // pkcs12はwc_d2i_PKCS12またはwc_d2i_PKCS12_fpでデコード済みとする

    // 返される秘密鍵にPKCS #8ヘッダーを残す
    if (wc_PKCS12_parse_ex(pkcs12, "password", &key, &keySz, &cert, &certSz,
                           &ca, 1) != 0) {
        // バンドルの解析エラー
    }

    XFREE(key, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(cert, NULL, DYNAMIC_TYPE_PKCS);
    wc_FreeCertList(ca, NULL);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_parse
    \sa wc_d2i_PKCS12
    \sa wc_FreeCertList
*/
int wc_PKCS12_parse_ex(WC_PKCS12* pkcs12, const char* psw,
        byte** pkey, word32* pkeySz, byte** cert, word32* certSz,
        WC_DerCertList** ca, int keepKeyHeader);

/*!
    \ingroup PKCS12

    \brief この関数は、DERエンコードされた秘密鍵、DERエンコードされた証明書、および任意の追加証明書のリストから、新しいWC_PKCS12構造体を作成します。鍵と証明書はそれぞれ独自のContentInfoに配置され、指定されたパスワードで任意に暗号化された上で、その結果に対してMACが計算されます。返された構造体はwc_i2d_PKCS12()でDERにエンコードでき、wc_PKCS12_free()で解放する必要があります。nidKey引数とnidCert引数は、それぞれ鍵と証明書に適用されるパスワードベース暗号化を選択します。指定できる値はPBE_SHA1_RC4_128、PBE_SHA1_DES、PBE_SHA1_DES3、PBE_AES128_CBC、PBE_AES256_CBCです。-1を渡すと、対応する内容は暗号化されずに格納されます。

    \note name引数とkeyType引数はAPIの互換性のために受け付けられますが、現在は使用されていません。

    \return pointer 成功時に、新たに作成されたWC_PKCS12構造体へのポインタを返します。
    \return NULL RNGの初期化に失敗した場合、メモリ割り当てに失敗した場合、サポートされていないnidKeyまたはnidCertが指定された場合、あるいはバンドルを構築できなかった場合に返されます。

    \param pass 暗号化とMACに使用するパスワード。
    \param passSz パスワードバッファのサイズ。
    \param name 使用するfriendlyName。現在は使用されていません。
    \param key DERエンコードされた秘密鍵を保持するバッファ。
    \param keySz 鍵バッファのサイズ。
    \param cert DERエンコードされた証明書を保持するバッファ。
    \param certSz 証明書バッファのサイズ。
    \param ca 任意。バンドルに含める追加のDERエンコード証明書のリンクリスト。不要な場合はNULLを指定します。
    \param nidKey 秘密鍵に適用する暗号化。暗号化しない場合は-1を指定します。
    \param nidCert 証明書に適用する暗号化。暗号化しない場合は-1を指定します。
    \param iter 暗号化に使用する反復回数。0以下の値を指定するとWC_PKCS12_ITT_DEFAULTが選択されます。
    \param macIter MACの作成に使用する反復回数。
    \param keyType 署名鍵または暗号化鍵を示すフラグ。現在は使用されていません。
    \param heap 動的メモリ割り当てに使用するヒープヒントへのポインタ。デフォルトを使用する場合はNULLを指定します。

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* der = NULL;
    char pass[] = "password";
    byte key[] = { };  // DERエンコードされた秘密鍵で初期化
    byte cert[] = { }; // DERエンコードされた証明書で初期化

    pkcs12 = wc_PKCS12_create(pass, sizeof(pass) - 1, NULL,
                              key, sizeof(key), cert, sizeof(cert), NULL,
                              PBE_AES256_CBC, PBE_AES256_CBC,
                              WC_PKCS12_ITT_DEFAULT, WC_PKCS12_ITT_DEFAULT,
                              0, NULL);
    if (pkcs12 == NULL) {
        // PKCS12バンドルの作成エラー
    }

    if (wc_i2d_PKCS12(pkcs12, &der, NULL) <= 0) {
        // バンドルのDERへのエンコードエラー
    }

    XFREE(der, NULL, DYNAMIC_TYPE_PKCS);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_i2d_PKCS12
    \sa wc_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_create(char* pass, word32 passSz,
        char* name, byte* key, word32 keySz, byte* cert, word32 certSz,
        WC_DerCertList* ca, int nidKey, int nidCert, int iter, int macIter,
        int keyType, void* heap);

/*!
    \ingroup PKCS12

    \brief この関数は、WC_DerCertListのリンクリストを、各ノードが保持するDERバッファも含めて解放します。wc_PKCS12_parse()およびwc_PKCS12_parse_ex()が返すCA証明書リストの解放に使用します。指定するヒープヒントは、そのリストの取得元であるWC_PKCS12構造体に関連付けられたものと一致している必要があります。listにNULLを渡しても安全で、その場合は何も行いません。

    \return none 戻り値はありません。

    \param list 解放するWC_DerCertListの先頭へのポインタ。
    \param heap リストの割り当て時に使用されたヒープヒントへのポインタ。

    _Example_
    \code
    WC_DerCertList* ca = NULL;

    // caは事前のwc_PKCS12_parseの呼び出しによって設定されているとする

    wc_FreeCertList(ca, NULL);
    \endcode

    \sa wc_PKCS12_parse
    \sa wc_PKCS12_parse_ex
*/
void wc_FreeCertList(WC_DerCertList* list, void* heap);
