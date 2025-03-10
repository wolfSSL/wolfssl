/*!
    \ingroup ASN
    \brief  この関数はCert構造体をデフォルトの値で初期化します。デフォルトのオプション：version = 3（0x2）、sigtype = sha_with_rsa、issuer =空白、dayValid = 500、selfsigned = 1（true）発行者としての件名=空白
    \return 成功した場合0を返します。

    _Example_
    \code
    Cert myCert;
    wc_InitCert(&myCert);
    \endcode
    \sa wc_MakeCert
    \sa wc_MakeCertReq
*/
int wc_InitCert(Cert*);

/*!
     \ingroup ASN

     \brief この関数は証明書操作の為に新たなCert構造体を割り当てます。
     割り当てたCert構造体はこの関数内で初期化されるので、wc_InitCert()を呼び出す必要はありません。
     アプリケーションがこのCert構造体の使用を終了する際にはwc_CertFree()を呼び出す必要があります。

     \return 処理が成功した際には新に割り当てられたCert構造体へのポインタを返します。
     \return メモリ確保に失敗した場合にはNULLを返します。

     \param メモリの動的確保で使用されるヒープへのポインタ。NULLの指定も可。

     _Example_
     \code
     Cert*   myCert;

     myCert = wc_CertNew(NULL);
     if (myCert == NULL) {
         // Cert creation failure
     }
     \endcode

     \sa wc_InitCert
     \sa wc_MakeCert
     \sa wc_CertFree

*/
Cert* wc_CertNew(void* heap);


/*!
     \ingroup ASN

     \brief この関数はwc_CertNew()で確保されたCert構造体を解放します。
     \return 無し
     \param 解放すべきCert構造体へのポインタ

     _Example_
     \code
     Cert*   myCert;

     myCert = wc_CertNew(NULL);

     // Perform cert operations.

     wc_CertFree(myCert);
     \endcode

     \sa wc_InitCert
     \sa wc_MakeCert
     \sa wc_CertNew

*/
void  wc_CertFree(Cert* cert);

/*!
    \ingroup ASN
    \brief  CA署名付き証明書を作成するために使用されます。
    サブジェクト情報を入力した後に呼び出す必要があります。
    この関数は、証明書入力からX.509v3 RSAまたはECC証明書を作成しderBufferに書き込みます。
    証明書を生成するためのRsaKeyまたはEccKeyのいずれかを引数として取ります。
    この関数が呼び出される前に、証明書をwc_InitCertで初期化する必要があります。

    \return 指定された入力証明書からX509証明書が正常に生成された場合、生成された証明書のサイズを返します。
    \return MEMORY_E  xmallocでのメモリ割り当でエラーが発生した場合に返ります。
    \return BUFFER_E  提供されたderBufferが生成された証明書を保存するには小さすぎる場合に返されます
    \return Others  証明書の生成が成功しなかった場合、追加のエラーメッセージが返される可能性があります。
    \param cert  初期化されたCert構造体へのポインタ
    \param derBuffer  生成された証明書を保持するバッファへのポインタ
    \param derSz  証明書を保存するバッファのサイズ
    \param rsaKey  証明書の生成に使用されるRSA鍵を含むRsaKey構造体へのポインタ
    \param eccKey  証明書の生成に使用されるECC鍵を含むEccKey構造体へのポインタ

    _Example_
    \code
    Cert myCert;
    wc_InitCert(&myCert);
    WC_RNG rng;
    //initialize rng;
    RsaKey key;
    //initialize key;
    byte * derCert = malloc(FOURK_BUF);
    word32 certSz;
    certSz = wc_MakeCert(&myCert, derCert, FOURK_BUF, &key, NULL, &rng);
    \endcode
    \sa wc_InitCert
    \sa wc_MakeCertReq
*/
int  wc_MakeCert(Cert* cert, byte* derBuffer, word32 derSz, RsaKey* rsaKey,
                             ecc_key* eccKey, WC_RNG* rng);

/*!
    \ingroup ASN
    \brief  この関数は、入力されたCert構造体を使用して証明書署名要求を作成しderBufferに書き込みます。
    証明書要求の生成にはRsaKeyまたはEccKeyのいずれかの鍵を受け取り使用します。
    この関数の後に、署名するためにwc_SignCert()を呼び出す必要があります。
    この関数の使用例については、wolfCryptテストアプリケーション(./wolfcrypt/test/test.c)を参照してください。
    \return 証明書署名要求が正常に生成されると、生成された証明書署名要求のサイズを返します。
    \return MEMORY_E  xmallocでのメモリ割り当てでエラーが発生した場合
    \return BUFFER_E  提供されたderBufferが生成された証明書を保存するには小さすぎる場合
    \return Other  証明書署名要求の生成が成功しなかった場合、追加のエラーメッセージが返される可能性があります。
    \param cert  初期化されたCert構造体へのポインタ
    \param derBuffer  生成された証明書署名要求を保持するバッファへのポインタ
    \param derSz  証明書署名要求を保存するバッファのサイズ
    \param rsaKey  証明書署名要求を生成するために使用されるRSA鍵を含むRsaKey構造体へのポインタ
    \param eccKey  証明書署名要求を生成するために使用されるRECC鍵を含むEccKey構造体へのポインタ

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    EccKey key;
    //initialize key;
    byte* derCert = (byte*)malloc(FOURK_BUF);

    word32 certSz;
    certSz = wc_MakeCertReq(&myCert, derCert, FOURK_BUF, NULL, &key);
    \endcode
    \sa wc_InitCert
    \sa wc_MakeCert
*/
int  wc_MakeCertReq(Cert* cert, byte* derBuffer, word32 derSz,
                                    RsaKey* rsaKey, ecc_key* eccKey);

/*!
    \ingroup ASN
    \brief  この関数はバッファーの内容に署名し、署名をバッファの最後に追加します。署名の種類を取ります。
    CA署名付き証明書を作成する場合は、wc_MakeCert()またはwc_MakeCertReq()の後に呼び出す必要があります。
    \return 証明書への署名に成功した場合は、証明書の新しいサイズ(署名を含む)を返します。
    \return MEMORY_E  xmallocでのメモリを割り当てでエラーがある場合
    \return BUFFER_E  提供された証明書を保存するには提供されたバッファが小さすぎる場合に返されます。
    \return Other  証明書の生成が成功しなかった場合、追加のエラーメッセージが返される可能性があります。
    \param requestSz  署名対象の証明書本文のサイズ
    \param sigType  作成する署名の種類。有効なオプションは次のとおりです:CTC_MD5WRSA、CTC_SHAWRSA、CTC_SHAWECDSA、CTC_SHA256WECDSA、ANDCTC_SHA256WRSA
    \param derBuffer  署名対象の証明書を含むバッファへのポインタ。関数の処理成功時には署名が付加された証明書を保持します。
    \param derSz  新たに署名された証明書を保存するバッファの（合計）サイズ
    \param rsaKey  証明書に署名するために使用されるRSA鍵を含むRsaKey構造体へのポインタ
    \param eccKey  証明書に署名するために使用されるECC鍵を含むEccKey構造体へのポインタ
    \param rng  署名に使用する乱数生成器(WC_RNG構造体)へのポインタ

    _Example_
    \code
    Cert myCert;
    byte* derCert = (byte*)malloc(FOURK_BUF);
    // initialize myCert, derCert
    RsaKey key;
    // initialize key;
    WC_RNG rng;
    // initialize rng

    word32 certSz;
    certSz = wc_SignCert(myCert.bodySz, myCert.sigType, derCert, FOURK_BUF,
    &key, NULL, &rng);
    \endcode
    \sa wc_InitCert
    \sa wc_MakeCert
*/
int  wc_SignCert(int requestSz, int sigType, byte* derBuffer,
                 word32 derSz, RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng);

/*!
    \ingroup ASN
    \brief  この関数は、以前の2つの関数、wc_MakeCert、および自己署名のためのwc_SignCertの組み合わせです（前の関数はCA要求に使用される場合があります）。
    証明書を作成してから、それに署名し、自己署名証明書を生成します。
    \return 証明書への署名が成功した場合は、証明書の新しいサイズを返します。
    \return MEMORY_E  xmallocでのメモリを割り当てでエラーがある場合
    \return BUFFER_E  提供された証明書を保存するには提供されたバッファが小さすぎる場合に返されます。
    \return Other  証明書の生成が成功しなかった場合、追加のエラーメッセージが返される可能性があります。
    \param cert  署名する対象のCert構造体へのポインタ
    \param derBuffer  署名付き証明書を保持するためのバッファへのポインタ
    \param derSz  署名付き証明書を保存するバッファのサイズ
    \param key  証明書に署名するために使用されるRSA鍵を含むRsaKey構造体へのポインタ
    \param rng  署名に使用する乱数生成器(WC_RNG構造体)へのポインタ

    _Example_
    \code
    Cert myCert;
    byte* derCert = (byte*)malloc(FOURK_BUF);
    // initialize myCert, derCert
    RsaKey key;
    // initialize key;
    WC_RNG rng;
    // initialize rng

    word32 certSz;
    certSz = wc_MakeSelfCert(&myCert, derCert, FOURK_BUF, &key, NULL, &rng);
    \endcode
    \sa wc_InitCert
    \sa wc_MakeCert
    \sa wc_SignCert
*/
int  wc_MakeSelfCert(Cert* cert, byte* derBuffer, word32 derSz, RsaKey* key,
                             WC_RNG* rng);

/*!
    \ingroup ASN

    \brief この関数はPEM形式のissureFileで与えられた発行者を証明書の発行者として設定します。
    また、その際に、証明書の自己署名プロパティをfalseに変更します。
    発行者は証明書の発行者として設定される前に検証されます。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書の発行者の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E  ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の発行者を検証することができない場合に返されます。

    \param cert 発行者を設定する対象のCert構造体へのポインタ
    \param issuerFile PEM形式の証明書ファイルへのファイルパス

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    if(wc_SetIssuer(&myCert, ”./path/to/ca-cert.pem”) != 0) {
    	// error setting issuer
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubject
    \sa wc_SetIssuerBuffer
*/
int  wc_SetIssuer(Cert* cert, const char* issuerFile);

/*!
    \ingroup ASN

    \brief この関数はPEM形式のsubjectFileで与えられた主体者を証明書の主体者として設定します。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書の主体者の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。

    \param 主体者を設定する対象のCert構造体へのポインタ
    \param subjectFile PEM形式の証明書ファイルへのファイルパス

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    if(wc_SetSubject(&myCert, ”./path/to/ca-cert.pem”) != 0) {
    	// error setting subject
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetSubject(Cert* cert, const char* subjectFile);


/*!
    \ingroup ASN

    \brief この関数はDER形式でバッファに格納されているRaw-Subject情報を証明書のRaw-Subject情報として設定します。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書のRaw-Subject情報の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。

    \param cert Raw-Subject情報を設定する対象のCert構造体へのポインタ
    \param der DER形式の証明書を格納しているバッファへのポインタ。この証明書のRaw-Subject情報が取り出されてcertに設定されます。
    \param derSz DER形式の証明書を格納しているバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetSubjectRaw(&myCert, der, FOURK_BUF) != 0) {
        // error setting subject
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubject
*/
int  wc_SetSubjectRaw(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数はCert構造体からRaw-Subject情報を取り出します。

    \return 0 証明書のRaw-Subject情報の取得に成功した場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。

    \param subjectRaw 処理が成功した際に返されるRaw-Subject情報を格納するバッファへのポインタのポインタ
    \param cert Raw-Subject情報を保持するCert構造体へのポインタ

    _Example_
    \code
    Cert myCert;
    byte *subjRaw;
    // initialize myCert

    if(wc_GetSubjectRaw(&subjRaw, &myCert) != 0) {
        // error setting subject
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubjectRaw
*/
int  wc_GetSubjectRaw(byte **subjectRaw, Cert *cert);

/*!
    \ingroup ASN

    \brief この関数は引数で与えられたPEM形式の証明書の主体者の別名をCert構造体に設定します。
    複数のドメインで同一の証明書を使用する際には主体者の別名を付与する機能は有用です。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書の主体者の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。

    \param cert 主体者の別名を設定する対象のCert構造体へのポインタ
    \param file PEM形式の証明書のファイルパス

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    if(wc_SetSubject(&myCert, ”./path/to/ca-cert.pem”) != 0) {
    	// error setting alt names
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetAltNames(Cert* cert, const char* file);

/*!
    \ingroup ASN

    \brief この関数はDER形式でバッファに格納されている発行者を証明書の発行者として設定します。
    加えて、証明書の事故署名プロパティをfalseに設定します。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書の発行者の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。

    \param cert 発行者を設定する対象のCert構造体へのポインタ
    \param der DER形式の証明書を格納しているバッファへのポインタ。この証明書の発行者情報が取り出されてcertに設定されます。
    \param derSz DER形式の証明書を格納しているバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetIssuerBuffer(&myCert, der, FOURK_BUF) != 0) {
	    // error setting issuer
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetIssuerBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数はDER形式でバッファに格納されているRaw-Issuer情報を証明書のRaw-Issuer情報として設定します。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書のRaw-Issuer情報の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。


    \param cert Raw-Issuer情報を設定する対象のCert構造体へのポインタ
    \param der DER形式の証明書を格納しているバッファへのポインタ。この証明書のRaw-Issuer情報が取り出されてcertに設定されます。
    \param derSz DER形式の証明書を格納しているバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetIssuerRaw(&myCert, der, FOURK_BUF) != 0) {
        // error setting subject
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetIssuerRaw(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数はDER形式でバッファに格納されている主体者を証明書の主体者として設定します。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書の主体者の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。

    \param cert 主体者を設定する対象のCert構造体へのポインタ
    \param der DER形式の証明書を格納しているバッファへのポインタ。この証明書の主体者が取り出されてcertに設定されます。
    \param derSz DER形式の証明書を格納しているバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetSubjectBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// error setting subject
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubject
*/
int  wc_SetSubjectBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数はDER形式でバッファに格納されている「別名情報」を証明書の「別名情報」として設定します。
    この機能は複数ドメインを一つの証明書を使ってセキュアにする際に有用です。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書の別名情報の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。

    \param cert 別名情報を設定する対象のCert構造体へのポインタ
    \param der DER形式の証明書を格納しているバッファへのポインタ。この証明書の別名情報が取り出されてcertに設定されます。
    \param derSz DER形式の証明書を格納しているバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetAltNamesBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// error setting subject
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetAltNames
*/
int  wc_SetAltNamesBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数はDER形式でバッファに格納されている「有効期間」情報を証明書の「有効期間」情報として設定します。
    この関数は証明書への署名に先立ち呼び出される必要があります。

    \return 0 証明書の有効期間情報の設定に成功した場合に返されます。
    \return MEMORY_E XMALLOCでメモリの確保に失敗した際に返されます。
    \return ASN_PARSE_E 証明書のヘッダーファイルの解析に失敗した際に返されます。
    \return ASN_OBJECT_ID_E 証明書の暗号タイプの解析でエラーが発生した際に返されます。
    \return ASN_EXPECT_0_E 証明書の暗号化仕様にフォーマットエラーが検出された際に返されます。
    \return ASN_BEFORE_DATE_E 証明書の使用開始日より前であった場合に返されます。
    \return ASN_AFTER_DATE_E 証明書の有効期限日より後であった場合に返されます。
    \return ASN_BITSTR_E 証明書のビットストリング要素の解析でエラーが発生した際に返されます。
    \return ECC_CURVE_OID_E 証明書のECC鍵の解析でエラーが発生した際に返されます。
    \return ASN_UNKNOWN_OID_E 証明書が未知のオブジェクトIDを使用していた際に返されます。
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSマクロが定義されていないのに証明書がV1あるいはV2形式であった場合に返されます。
    \return BAD_FUNC_ARG 証明書の拡張情報の解析でエラーが発生した際に返されます。
    \return ASN_CRIT_EXT_E 証明書の解析中に未知のクリティカル拡張に遭遇した際に返されます。
    \return ASN_SIG_OID_E 署名暗号化タイプが引数で渡された証明書のタイプと異なる場合に返されます。
    \return ASN_SIG_CONFIRM_E 証明書の署名の検証に失敗した際に返されます。
    \return ASN_NAME_INVALID_E 証明書の名前がCAの名前に関数制限によって許されていない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。
    \return ASN_NO_SIGNER_E CA証明書の主体者を検証することができない場合に返されます。

    \param cert 有効期間情報を設定する対象のCert構造体へのポインタ
    \param der DER形式の証明書を格納しているバッファへのポインタ。この証明書の有効期間情報が取り出されてcertに設定されます。
    \param derSz DER形式の証明書を格納しているバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetDatesBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// error setting subject
    }
    \endcode

    \sa wc_InitCert
*/
int  wc_SetDatesBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数は指定されたRSAあるいはECC公開鍵の一方から得たAKID（認証者鍵ID）を証明書のAKIDとして設定します。

    \return 0 証明書のAKIDの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG Cert構造体へのポインタ(cert)がNULLかRsaKey構造体へのポインタ(rsakey)とecc_key構造体へのポインタ(eckey)の両方がNULLである場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return PUBLIC_KEY_E 公開鍵の取得に失敗した際に返されます。

    \param cert AKIDを設定する対象のCert構造体へのポインタ
    \param rsakey RsaKey構造体へのポインタ
    \param eckey ecc_key構造体へのポインタ

    _Example_
    \code
    Cert myCert;
    RsaKey keypub;

    wc_InitRsaKey(&keypub, 0);

    if (wc_SetAuthKeyIdFromPublicKey(&myCert, &keypub, NULL) != 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_SetSubjectKeyId
    \sa wc_SetAuthKeyId
    \sa wc_SetAuthKeyIdFromCert
*/
int wc_SetAuthKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey,
                                             ecc_key *eckey);

/*!
    \ingroup ASN

    \brief この関数はDER形式でバッファに格納された証明書から得たAKID(認証者鍵ID)を証明書のAKIDとして設定します。

    \return 0 証明書のAKIDの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 引数のいずれかがNULL,あるいはderSzが０より小さい場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return ASN_NO_SKID 認証者鍵IDが見つからない場合に返されます。

    \param cert AKIDを設定する対象のCert構造体へのポインタ。
    \param der DER形式の証明書を格納しているバッファへのポインタ。
    \param derSz DER形式の証明書を格納しているバッファのサイズ。

    _Example_
    \code
    Cert some_cert;
    byte some_der[] = { // Initialize a DER buffer };
    wc_InitCert(&some_cert);
    if(wc_SetAuthKeyIdFromCert(&some_cert, some_der, sizeof(some_der) != 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_SetAuthKeyIdFromPublicKey
    \sa wc_SetAuthKeyId
*/
int wc_SetAuthKeyIdFromCert(Cert *cert, const byte *der, int derSz);

/*!
    \ingroup ASN

    \brief この関数はPEM形式の証明書から得たAKID(認証者鍵ID)を証明書のAKIDとして設定します。

    \return 0 証明書のAKIDの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 引数のいずれかがNULLの場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。

    \param cert AKIDを設定する対象のCert構造体へのポインタ。
    \param file PEM形式の証明書ファイルへのファイルパス

    _Example_
    \code
    char* file_name = "/path/to/file";
    cert some_cert;
    wc_InitCert(&some_cert);

    if(wc_SetAuthKeyId(&some_cert, file_name) != 0)
    {
        // Handle Error
    }
    \endcode

    \sa wc_SetAuthKeyIdFromPublicKey
    \sa wc_SetAuthKeyIdFromCert
*/
int wc_SetAuthKeyId(Cert *cert, const char* file);

/*!
    \ingroup ASN

    \brief この関数は指定されたRSAあるいはECC公開鍵の一方から得たSKID（主体者鍵ID）を証明書のSKIDとして設定します。

    \return 0 証明書のSKIDの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG Cert構造体へのポインタ(cert)がNULLかRsaKey構造体へのポインタ(rsakey)とecc_key構造体へのポインタ(eckey)の両方がNULLである場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return PUBLIC_KEY_E 公開鍵の取得に失敗した際に返されます。

    \param cert SKIDを設定する対象のCert構造体へのポインタ
    \param rsakey RsaKey構造体へのポインタ
    \param eckey ecc_key構造体へのポインタ

    _Example_
    \code
    Cert some_cert;
    RsaKey some_key;
    wc_InitCert(&some_cert);
    wc_InitRsaKey(&some_key);

    if(wc_SetSubjectKeyIdFromPublicKey(&some_cert,&some_key, NULL) != 0)
    {
        // Handle Error
    }
    \endcode

    \sa wc_SetSubjectKeyId
*/
int wc_SetSubjectKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey,
                                                ecc_key *eckey);

/*!
    \ingroup ASN

    \brief この関数はPEM形式の証明書から得たSKID(主体者鍵ID)を証明書のSKIDとして設定します。
    引数は両方が与えられることが必要です。

    \return 0 証明書のSKIDの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 引数のいずれかがNULLの場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return PUBLIC_KEY_E 公開鍵のデコードに失敗した際に返されます。

    \param cert SKIDを設定する対象のCert構造体へのポインタ。
    \param file PEM形式の証明書ファイルへのファイルパス

    _Example_
    \code
    const char* file_name = "path/to/file";
    Cert some_cert;
    wc_InitCert(&some_cert);

    if(wc_SetSubjectKeyId(&some_cert, file_name) != 0)
    {
        // Handle Error
    }
    \endcode

    \sa wc_SetSubjectKeyIdFromPublicKey
*/
int wc_SetSubjectKeyId(Cert *cert, const char* file);

/*!
    \ingroup RSA

    \brief この関数は鍵の用途を設定します。設定値の指定はコンマ区切りトークンを使用できます。
    受け付けられるトークンは：digitalSignature, nonRepudiation, contentCommitment, keyCertSign, cRLSign, dataEncipherment,
    keyAgreement, keyEncipherment, encipherOnly, decipherOnly です。
    指定例："digitalSignature,nonRepudiation"。
    nonRepudiation と contentCommitment　は同じ用途を意味します。

    \return 0 証明書の用途の設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 引数のいずれかがNULLの場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return KEYUSAGE_E 未知のトークンが検出された際に返されます。

    \param cert 鍵の用途を設定する対象の初期化済みCert構造体へのポインタ。
    \param value 鍵の用途を意味するコンマ区切りトークン文字列へのポインタ

    _Example_
    \code
    Cert cert;
    wc_InitCert(&cert);

    if(wc_SetKeyUsage(&cert, "cRLSign,keyCertSign") != 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_InitCert
    \sa wc_MakeRsaKey
*/
int wc_SetKeyUsage(Cert *cert, const char *value);

/*!
    \ingroup ASN

    \brief PEM形式の鍵ファイルをロードしDER形式に変換してバッファに出力します。

    \return 0 処理成功時に返されます。
    \return <0 エラー発生時に返されます。
    \return SSL_BAD_FILE ファイルのオープンに問題が生じた際に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return BUFFER_E 与えられた出力バッファderBufが結果を保持するのに十分な大きさがない場合に返されます。

    \param fileName PEM形式のファイルパス
    \param derBuf DER形式鍵を出力する先のバッファ
    \param derSz 出力先バッファのサイズ

    _Example_
    \code
    char* some_file = "filename";
    unsigned char der[];

    if(wc_PemPubKeyToDer(some_file, der, sizeof(der)) != 0)
    {
        //Handle Error
    }
    \endcode

    \sa wc_PubKeyPemToDer
*/
int wc_PemPubKeyToDer(const char* fileName,
                                       unsigned char* derBuf, int derSz);

/*!
    \ingroup ASN

    \brief PEM形式の鍵データをDER形式に変換してバッファに出力し、出力バイト数あるいは負のエラー値を返します。

    \return >0 処理成功時には出力したバイト数が返されます。
    \return BAD_FUNC_ARG 引数のpem, buff, あるいは buffSz のいずれかばNULLの場合に返されます。
    \return <0 エラーが発生した際に返されます。

    \param pem PEM形式の鍵を含んだバッファへのポインタ
    \param pemSz PEM形式の鍵を含んだバッファのサイズ
    \param buff 出力先バッファへのポインタ
    \param buffSz 出力先バッファのサイズ

    _Example_
    \code
    byte some_pem[] = { Initialize with PEM key }
    unsigned char out_buffer[1024]; // Ensure buffer is large enough to fit DER

    if(wc_PubKeyPemToDer(some_pem, sizeof(some_pem), out_buffer,
    sizeof(out_buffer)) < 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_PemPubKeyToDer
*/
int wc_PubKeyPemToDer(const unsigned char* pem, int pemSz,
                                      unsigned char* buff, int buffSz);

/*!
    \ingroup ASN

    \brief この関数はPEM形式の証明書をDER形式に変換し、与えられたバッファに出力します。

    \return 処理成功時には出力したバイト数が返されます。
    \return BUFFER_E 与えられた出力バッファderBufが結果を保持するのに十分な大きさがない場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。

    \param fileName PEM形式のファイルパス
    \param derBuf DER形式証明書を出力する先のバッファへのポインタ
    \param derSz DER形式証明書を出力する先のバッファのサイズ

    _Example_
    \code
    char * file = “./certs/client-cert.pem”;
    int derSz;
    byte* der = (byte*)XMALLOC((8*1024), NULL, DYNAMIC_TYPE_CERT);

    derSz = wc_PemCertToDer(file, der, (8*1024));
    if (derSz <= 0) {
        //PemCertToDer error
    }
    \endcode

    \sa none
*/

int wc_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz);

/*!
    \ingroup ASN

    \brief この関数はバッファで与えられたDER形式の証明書をPEM形式に変換し、与えられた出力用バッファに出力します。
    この関数は入力バッファと出力バッファを共用することはできません。両バッファは必ず別のものを用意してください。

    \return 処理成功時には変換後のPEM形式データのサイズを返します。
    \return BAD_FUNC_ARG DER形式証明書データの解析中にエラーが発生した際、あるいはPEM形式に変換の際にエラーが発生した際に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return ASN_INPUT_E Base64エンコーディングエラーが検出された際に返されます。
    \return BUFFER_E 与えられた出力バッファが結果を保持するのに十分な大きさがない場合に返されます。

    \param der DER形式証明書データを保持するバッファへのポインタ
    \param derSz DER形式証明書データのサイズ
    \param output PEM形式証明書データを出力する先のバッファへのポインタ
    \param outSz PEM形式証明書データを出力する先のバッファのサイズ
    \param type 変換する証明書のタイプ。次のタイプが指定可: CERT_TYPE, PRIVATEKEY_TYPE, ECC_PRIVATEKEY_TYPE, and CERTREQ_TYPE.

    _Example_
    \code
    byte* der;
    // initialize der with certificate
    byte* pemFormatted[FOURK_BUF];

    word32 pemSz;
    pemSz = wc_DerToPem(der, derSz,pemFormatted,FOURK_BUF, CERT_TYPE);
    \endcode

    \sa wc_PemCertToDer
*/
int wc_DerToPem(const byte* der, word32 derSz, byte* output,
                                word32 outputSz, int type);

/*!
    \ingroup ASN

    \brief この関数はDER形式証明書を入力バッファから読み出し、PEM形式に変換して出力バッファに出力します。
    この関数は入力バッファと出力バッファを共用することはできません。両バッファは必ず別のものを用意してください。
    追加の暗号情報を指定することができます。

    \return 処理成功時には変換後のPEM形式データのサイズを返します。
    \return BAD_FUNC_ARG Returned DER形式証明書データの解析中にエラーが発生した際、あるいはPEM形式に変換の際にエラーが発生した際に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return ASN_INPUT_E Base64エンコーディングエラーが検出された際に返されます。
    \return BUFFER_E 与えられた出力バッファが結果を保持するのに十分な大きさがない場合に返されます。

    \param der DER形式証明書データを保持するバッファへのポインタ
    \param derSz DER形式証明書データのサイズ
    \param output PEM形式証明書データを出力する先のバッファへのポインタ
    \param outSz PEM形式証明書データを出力する先のバッファのサイズ
    \param cipher_inf 追加の暗号情報
    \param type 生成する証明書タイプ。指定可能なタイプ: CERT_TYPE, PRIVATEKEY_TYPE, ECC_PRIVATEKEY_TYPE と CERTREQ_TYPE

    _Example_
    \code
    byte* der;
    // initialize der with certificate
    byte* pemFormatted[FOURK_BUF];

    word32 pemSz;
    byte* cipher_info[] { Additional cipher info. }
    pemSz = wc_DerToPemEx(der, derSz, pemFormatted, FOURK_BUF, cipher_info, CERT_TYPE);
    \endcode

    \sa wc_PemCertToDer
*/
int wc_DerToPemEx(const byte* der, word32 derSz, byte* output,
                                word32 outputSz, byte *cipherIno, int type);

/*!
    \ingroup CertsKeys

    \brief PEM形式の鍵をDER形式に変換します。

    \return 変換に成功した際には出力バッファに書き込んだデータサイズを返します。
    \return エラー発生時には負の整数値を返します。

    \param pem PEM形式の証明書データへのポインタ
    \param pemSz PEM形式の証明書データのサイズ
    \param buff DerBuffer構造体のbufferメンバーのコピーへのポインタ
    \param buffSz DerBuffer構造体のbufferメンバーへ確保されたバッファのサイズ
    \param pass パスワード

    _Example_
    \code
    byte* loadBuf;
    long fileSz = 0;
    byte* bufSz;
    static int LoadKeyFile(byte** keyBuf, word32* keyBufSz,
    const char* keyFile,
                    int typeKey, const char* password);
    …
    bufSz = wc_KeyPemToDer(loadBuf, (int)fileSz, saveBuf,
    (int)fileSz, password);

    if(saveBufSz > 0){
        // Bytes were written to the buffer.
    }
    \endcode

    \sa wc_PemToDer
*/
int wc_KeyPemToDer(const unsigned char* pem, int pemSz,
                                    unsigned char* buff, int buffSz, const char* pass);

/*!
    \ingroup CertsKeys

    \brief この関数はPEM形式の証明書をDER形式に変換します。内部ではOpenSSL互換APIのPemToDerを呼び出します。

    \return バッファに出力したサイズを返します。

    \param pem PEM形式の証明書を含むバッファへのポインタ
    \param pemSz PEM形式の証明書を含むバッファのサイズ
    \param buff DER形式に変換した証明書データの出力先バッファへのポインタ
    \param buffSz 出力先バッファのサイズ
    \param type 証明書のタイプ。asn_public.h で定義のenum CertTypeの値。

    _Example_
    \code
    const unsigned char* pem;
    int pemSz;
    unsigned char buff[BUFSIZE];
    int buffSz = sizeof(buff)/sizeof(char);
    int type;
    ...
    if(wc_CertPemToDer(pem, pemSz, buff, buffSz, type) <= 0) {
        // There were bytes written to buffer
    }
    \endcode

    \sa wc_PemToDer
*/
int wc_CertPemToDer(const unsigned char* pem, int pemSz,
                    unsigned char* buff, int buffSz, int type);

/*!
    \ingroup CertsKeys

    \brief この関数は公開鍵をDER形式でDecodedCert構造体から取り出します。
    wc_InitDecodedCert()とwc_ParseCert()を事前に呼び出しておく必要があります。
    wc_InitDecodedCert()はDER/ASN.1エンコードされた証明書を受け付けます。
    PEM形式の鍵をDER形式で取得する場合には、wc_InitDecodedCert()より先にwc_CertPemToDer()を呼び出してください。

    \return 成功時に0を返します。エラー発生時には負の整数を返します。
    \return LENGTH_ONLY_E derKeyがNULLの際に返されます。

    \param cert X.509証明書を保持したDecodedCert構造体へのポインタ
    \param derKey DER形式の公開鍵を出力する先のバッファへのポインタ
    \param derKeySz [IN/OUT] 入力時にはderKeyで与えられるバッファのサイズ,出力時には公開鍵のサイズを保持します。
    もし、derKeyがNULLで渡された場合には, derKeySzには必要なバッファサイズが格納され、LENGTH_ONLY_Eが戻り値として返されます。

    \sa wc_GetPubKeyDerFromCert
*/
int wc_GetPubKeyDerFromCert(struct DecodedCert* cert,
                                        byte* derKey, word32* derKeySz);

/*!
    \ingroup ASN

    \brief この関数はECC秘密鍵を入力バッファから読み込み、解析の後ecc_key構造体を作成してそこに鍵を格納します。

    \return 0 秘密鍵のデコードと結果のecc_key構造体への格納成功時に返されます。
    \return ASN_PARSE_E 入力バッファの解析あるいは結果の格納時にエラーが発生した場合に返されます。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return BUFFER_E 入力された証明書が最大証明書サイズより大きかった場合に返されます。
    \return ASN_OBJECT_ID_E 証明書が無効なオブジェクトIDを含んでいる場合に返されます。
    \return ECC_CURVE_OID_E 与えられた秘密鍵のECC曲線がサポートされていない場合に返されます。
    \return ECC_BAD_ARG_E ECC秘密鍵のフォーマットにエラーがある場合に返されます。
    \return NOT_COMPILED_IN 秘密鍵が圧縮されていて圧縮鍵が提供されていない場合に返されます。
    \return MP_MEM 秘密鍵の解析で使用される数学ライブラリがエラーを検出した場合に返されます。
    \return MP_VAL 秘密鍵の解析で使用される数学ライブラリがエラーを検出した場合に返されます。
    \return MP_RANGE 秘密鍵の解析で使用される数学ライブラリがエラーを検出した場合に返されます。

    \param input 入力となる秘密鍵データを含んでいるバッファへのポインタ
    \param inOutIdx word32型変数で内容として入力バッファの処理開始位置を先頭からのインデクス値として保持している。
    \param key デコードされた秘密鍵が格納される初期化済みのecc_key構造体へのポインタ
    \param inSz 秘密鍵を含んでいる入力バッファのサイズ

    _Example_
    \code
    int ret, idx=0;
    ecc_key key; // to store key in

    byte* tmp; // tmp buffer to read key from
    tmp = (byte*) malloc(FOURK_BUF);

    int inSz;
    inSz = fread(tmp, 1, FOURK_BUF, privateKeyFile);
    // read key into tmp buffer

    wc_ecc_init(&key); // initialize key
    ret = wc_EccPrivateKeyDecode(tmp, &idx, &key, (word32)inSz);
    if(ret < 0) {
        // error decoding ecc key
    }
    \endcode

    \sa wc_RSA_PrivateKeyDecode
*/
int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx,
                                           ecc_key* key, word32 inSz);

/*!
    \ingroup ASN

    \brief この関数はECC秘密鍵をDER形式でバッファに出力します。

    \return ECC秘密鍵をDER形式での出力に成功した場合にはバッファへ出力したサイズを返します。
    \return BAD_FUNC_ARG 出力バッファoutputがNULLあるいはinLenがゼロの場合に返します。
    \return MEMORY_E メモリの確保に失敗した際に返されます。
    \return BUFFER_E 出力バッファが必要量より小さい
    \return ASN_UNKNOWN_OID_E ECC秘密鍵が未知のタイプの場合に返します。
    \return MP_MEM 秘密鍵の解析で使用される数学ライブラリがエラーを検出した場合に返されます。
    \return MP_VAL 秘密鍵の解析で使用される数学ライブラリがエラーを検出した場合に返されます。
    \return MP_RANGE 秘密鍵の解析で使用される数学ライブラリがエラーを検出した場合に返されます。

    \param key 入力となるECC秘密鍵データを含んでいるバッファへのポインタ
    \param output DER形式のECC秘密鍵を出力する先のバッファへのポインタ
    \param inLen DER形式のECC秘密鍵を出力する先のバッファのサイズ

    _Example_
    \code
    int derSz;
    ecc_key key;
    // initialize and make key
    byte der[FOURK_BUF];
    // store der formatted key here

    derSz = wc_EccKeyToDer(&key, der, FOURK_BUF);
    if(derSz < 0) {
        // error converting ecc key to der buffer
    }
    \endcode

    \sa wc_RsaKeyToDer
*/
int wc_EccKeyToDer(ecc_key* key, byte* output, word32 inLen);

/*!
    \ingroup ASN

    \brief この関数は入力バッファのECC公開鍵をASNシーケンスをデコードして取り出します。

    \return 0 処理成功時に返します。
    \return BAD_FUNC_ARG Returns いずれかの引数がNULLの場合に返します。
    \return ASN_PARSE_E 解析中にエラーが発生した場合に返します。
    \return ASN_ECC_KEY_E 鍵のインポートでエラーが発生した場合に返します。
    発生理由についてはwc_ecc_import_x963()を参照のこと。

    \param input DER形式の公開鍵を含んだバッファへのポインタ
    \param inOutIdx バッファの読み出し位置インデクス値を保持している変数へのポインタ(入力時)。
    出力時にはこの変数に解析済みのバッファのインデクス値が格納されます。
    \param key ecc_key構造体へのポインタ
    \param inSz 入力バッファのサイズ

    _Example_
    \code
    int ret;
    word32 idx = 0;
    byte buff[] = { // initialize with key };
    ecc_key pubKey;
    wc_ecc_init(&pubKey);
    if ( wc_EccPublicKeyDecode(buff, &idx, &pubKey, sizeof(buff)) != 0) {
            // error decoding key
    }
    \endcode

    \sa wc_ecc_import_x963
*/
int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
                          ecc_key* key, word32 inSz);

/*!
    \ingroup ASN

    \brief この関数はECC公開鍵をDER形式に変換します。
    処理したバッファのサイズを返します。変換して得られるDER形式のECC公開鍵は出力バッファに格納されます。
    AlgCurveフラグの指定により、アルゴリズムと曲線情報をヘッダーに含めることができます。

    \return 成功時には処理したバッファのサイズを返します。
    \return BAD_FUNC_ARG 出力バッファoutputあるいはecc_key構造体keyがNULLの場合に返します。
    \return LENGTH_ONLY_E ECC公開鍵のサイズ取得に失敗した場合に返します。
    \return BUFFER_E 出力バッファが必要量より小さい場合に返します。

    \param key ecc_key構造体へのポインタ
    \param output 出力バッファへのポインタ
    \param inLen 出力バッファのサイズ
    \param with_AlgCurve アルゴリズムと曲線情報をヘッダーに含める際には１を指定

    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    int derSz = // Some appropriate size for der;
    byte der[derSz];

    if(wc_EccPublicKeyToDer(&key, der, derSz, 1) < 0)
    {
        // Error converting ECC public key to der
    }
    \endcode

    \sa wc_EccKeyToDer
    \sa wc_EccPrivateKeyDecode
*/
int wc_EccPublicKeyToDer(ecc_key* key, byte* output,
                                         word32 inLen, int with_AlgCurve);

/*!
    \ingroup ASN

    \brief この関数はECC公開鍵をDER形式に変換します。
    処理したバッファサイズを返します。変換されたDER形式のECC公開鍵は出力バッファに格納されます。
    AlgCurveフラグの指定により、アルゴリズムと曲線情報をヘッダーに含めることができます。
    compパラメータは公開鍵を圧縮して出力するか否かを指定します。

    \return >0 成功時には処理したバッファのサイズを返します。
    \return BAD_FUNC_ARG 出力バッファoutputあるいはecc_key構造体keyがNULLの場合に返します。
    \return LENGTH_ONLY_E ECC公開鍵のサイズ取得に失敗した場合に返します。
    \return BUFFER_E 出力バッファが必要量より小さい場合に返します。

    \param key ecc_key構造体へのポインタ
    \param output 出力バッファへのポインタ
    \param inLen 出力バッファのサイズ
    \param with_AlgCurve アルゴリズムと曲線情報をヘッダーに含める際には１を指定
    \param comp 非ゼロ値の指定時にはECC公開鍵は圧縮形式で出力されます。ゼロが指定された場合には非圧縮で出力されます。

    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    int derSz = // Some appropriate size for der;
    byte der[derSz];

    // Write out a compressed ECC key
    if(wc_EccPublicKeyToDer_ex(&key, der, derSz, 1, 1) < 0)
    {
        // Error converting ECC public key to der
    }
    \endcode

    \sa wc_EccKeyToDer
    \sa wc_EccPublicKeyDecode
*/
int wc_EccPublicKeyToDer_ex(ecc_key* key, byte* output,
                                     word32 inLen, int with_AlgCurve, int comp);

/*!
    \ingroup ASN

    \brief この関数はデジタル署名をエンコードして出力バッファに出力し、生成された署名のサイズを返します。

    \return 成功時には署名を出力バッファに出力し、出力したサイズを返します。

    \param out エンコードした署名データを出力する先のバッファへのポインタ
    \param digest 署名データのエンコードに使用するダイジェストへのポインタ
    \param digSz ダイジェストを含んでいるバッファのサイズ
    \param hashOID ハッシュタイプを示すオブジェクトID。有効な値は: SHAh, SHA256h, SHA384h, SHA512h, MD2h, MD5h, DESb, DES3b, CTC_MD5wRSA,
    CTC_SHAwRSA, CTC_SHA256wRSA, CTC_SHA384wRSA, CTC_SHA512wRSA, CTC_SHAwECDSA, CTC_SHA256wECDSA, CTC_SHA384wECDSA, と CTC_SHA512wECDSA。

    \endcode
    \code
    int signSz;
    byte encodedSig[MAX_ENCODED_SIG_SZ];
    Sha256 sha256;
    // initialize sha256 for hashing

    byte* dig = = (byte*)malloc(WC_SHA256_DIGEST_SIZE);
    // perform hashing and hash updating so dig stores SHA-256 hash
    // (see wc_InitSha256, wc_Sha256Update and wc_Sha256Final)
    signSz = wc_EncodeSignature(encodedSig, dig, WC_SHA256_DIGEST_SIZE, SHA256h);
    \endcode

    \sa none
*/
word32 wc_EncodeSignature(byte* out, const byte* digest,
                                      word32 digSz, int hashOID);

/*!
    \ingroup ASN

    \brief この関数はハッシュタイプに対応したハッシュOIDを返します。
    例えば、ハッシュタイプが"WC_SHA512"の場合、この関数は"SHA512h"を対応するハッシュOIDとして返します。

    \return 成功時には指定されたハッシュタイプと対応するハッシュOIDを返します。
    \return 0 認識できないハッシュタイプが引数として指定された場合に返します。

    \param type ハッシュタイプ。指定可能なタイプ: WC_MD5, WC_SHA, WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384, WC_SHA3_512

    _Example_
    \code
    int hashOID;

    hashOID = wc_GetCTC_HashOID(WC_SHA512);
    if (hashOID == 0) {
	    // WOLFSSL_SHA512 not defined
    }
    \endcode

    \sa none
*/
int wc_GetCTC_HashOID(int type);

/*!
    \ingroup ASN

    \brief この関数はキャッシュされていたCert構造体で使用されたメモリとリソースをクリーンアップします。
     WOLFSSL_CERT_GEN_CACHEが定義されている場合にはDecodedCert構造体がCert構造体内部にキャッシュされ、後続するset系関数の呼び出しの都度DecodedCert構造体がパースされることを防ぎます。

    \return 0 成功時に返されます。
    \return BAD_FUNC_ARG 引数として無効な値が渡された場合に返されます。

    \param cert 未初期化のCert構造体へのポインタ

    _Example_
    \code
    Cert cert; // Initialized certificate structure

    wc_SetCert_Free(&cert);
    \endcode

    \sa wc_SetAuthKeyIdFromCert
    \sa wc_SetIssuerBuffer
    \sa wc_SetSubjectBuffer
    \sa wc_SetSubjectRaw
    \sa wc_SetIssuerRaw
    \sa wc_SetAltNamesBuffer
    \sa wc_SetDatesBuffer
*/
void wc_SetCert_Free(Cert* cert);

/*!
    \ingroup ASN

    \brief この関数はPKCS#8の暗号化されていないバッファ内部の従来の秘密鍵の開始位置を検出して返します。

    \return 成功時には従来の秘密鍵の長さを返します。
    \return エラー時には負の整数値を返します。

    \param input PKCS#8の暗号化されていない秘密鍵を保持するバッファへのポインタ
    \param inOutIdx バッファのインデクス位置を保持する変数へのポインタ。入力時にはこの変数の内容はバッファ内部のPKCS#8の開始位置を示します。出力時には、秘密鍵の先頭位置を保持します。
    \param sz 入力バッファのサイズ

    _Example_
    \code
    byte* pkcs8Buf; // Buffer containing PKCS#8 key.
    word32 idx = 0;
    word32 sz; // Size of pkcs8Buf.
    ...
    ret = wc_GetPkcs8TraditionalOffset(pkcs8Buf, &idx, sz);
    // pkcs8Buf + idx is now the beginning of the traditional private key bytes.
    \endcode

    \sa wc_CreatePKCS8Key
    \sa wc_EncryptPKCS8Key
    \sa wc_DecryptPKCS8Key
    \sa wc_CreateEncryptedPKCS8Key
*/
int wc_GetPkcs8TraditionalOffset(byte* input,
                                             word32* inOutIdx, word32 sz);

/*!
    \ingroup ASN

    \brief この関数はDER形式の秘密鍵を入力とし、RKCS#8形式に変換します。
    また、PKCS#12のシュロ―ディットキーバッグの作成にも使用できます。RFC5208を参照のこと。

    \return 成功時には出力されたPKCS#8 鍵のサイズを返します。
    \return LENGTH_ONLY_E 出力先バッファoutがNULLとして渡された場合にはこのエラーコードが返され、outSzに必要な出力バッファのサイズが格納されます。
    \return エラー時には負の整数値が返されます。

    \param out 結果の出力先バッファへのポインタ。NULLの場合には必要な出力先バッファのサイズがoutSzに格納されます。
    \param outSz 出力先バッファのサイズ
    \param key 従来のDER形式の秘密鍵を含むバッファへのポインタ
    \param keySz 秘密鍵を含むバッファのサイズ
    \param algoID アルゴリズムID (RSAk等の)
    \param curveOID ECC曲線OID。RSA鍵を使用する場合にはNULLにすること。
    \param oidSz ECC曲線OIDのサイズ。curveOIDがNULLの場合には0にすること。

    _Example_
    \code
    ecc_key eccKey;              // wolfSSL ECC key object.
    byte* der;                   // DER-encoded ECC key.
    word32 derSize;              // Size of der.
    const byte* curveOid = NULL; // OID of curve used by eccKey.
    word32 curveOidSz = 0;       // Size of curve OID.
    byte* pkcs8;                 // Output buffer for PKCS#8 key.
    word32 pkcs8Sz;              // Size of output buffer.

    derSize = wc_EccKeyDerSize(&eccKey, 1);
    ...
    derSize = wc_EccKeyToDer(&eccKey, der, derSize);
    ...
    ret = wc_ecc_get_oid(eccKey.dp->oidSum, &curveOid, &curveOidSz);
    ...
    ret = wc_CreatePKCS8Key(NULL, &pkcs8Sz, der,
        derSize, ECDSAk, curveOid, curveOidSz); // Get size needed in pkcs8Sz.
    ...
    ret = wc_CreatePKCS8Key(pkcs8, &pkcs8Sz, der,
        derSize, ECDSAk, curveOid, curveOidSz);
    \endcode

    \sa wc_GetPkcs8TraditionalOffset
    \sa wc_EncryptPKCS8Key
    \sa wc_DecryptPKCS8Key
    \sa wc_CreateEncryptedPKCS8Key
*/
int wc_CreatePKCS8Key(byte* out, word32* outSz,
        byte* key, word32 keySz, int algoID, const byte* curveOID,
        word32 oidSz);

/*!
    \ingroup ASN

    \brief この関数は暗号化されていないPKCS#8のDER形式の鍵(例えばwc_CreatePKCS8Keyで生成された鍵)を受け取り、PKCS#8 暗号化形式に変換します。
     結果として得られた暗号化鍵はwc_DecryptPKCS8Keyを使って復号できます。RFC5208を参照してください。

    \return 成功時には出力先バッファに出力された暗号化鍵のサイズを返します。
    \return LENGTH_ONLY_E 出力先バッファoutがNULLとして渡された場合にはこのエラーコードが返され、outSzに必要な出力バッファのサイズが格納されます。
    \return エラー時には負の整数値が返されます。

    \param key 従来のDER形式の鍵を含んだバッファへのポインタ
    \param keySz 鍵を含んだバッファのサイズ
    \param out 出力結果を格納する先のバッファへのポインタ。NULLの場合には必要な出力先バッファのサイズがoutSzに格納されます。
    \param outSz 出力先バッファのサイズ
    \param password パスワードベース暗号化アルゴリズムに使用されるパスワード
    \param passwordSz パスワードのサイズ(NULL終端文字は含まない)
    \param vPKCS 使用するPKCSのバージョン番号。1 はPKCS12 かPKCS5。
    \param pbeOid パスワードベース暗号化スキームのOID(PBES2 あるいはRFC2898 A.3にあるOIDの一つ)
    \param encAlgId 暗号化アルゴリズムID(例えばAES256CBCb)。
    \param salt ソルト。NULLの場合はランダムに選定したソルトが使用されます。
    \param saltSz ソルトサイズ。saltにNULLを渡した場合には0を指定できます。
    \param itt 鍵導出のための繰り返し回数
    \param rng 初期化済みのWC_RNG構造体へのポインタ
    \param heap 動的メモリ確保のためのヒープ。NULL指定も可。

    _Example_
    \code
    byte* pkcs8;          // Unencrypted PKCS#8 key.
    word32 pkcs8Sz;       // Size of pkcs8.
    byte* pkcs8Enc;       // Encrypted PKCS#8 key.
    word32 pkcs8EncSz;    // Size of pkcs8Enc.
    const char* password; // Password to use for encryption.
    int passwordSz;       // Length of password (not including NULL terminator).
    WC_RNG rng;

    // The following produces an encrypted version of pkcs8 in pkcs8Enc. The
    // encryption uses password-based encryption scheme 2 (PBE2) from PKCS#5 and
    // the AES cipher in CBC mode with a 256-bit key. See RFC 8018 for more on
    // PKCS#5.
    ret = wc_EncryptPKCS8Key(pkcs8, pkcs8Sz, pkcs8Enc, &pkcs8EncSz, password,
            passwordSz, PKCS5, PBES2, AES256CBCb, NULL, 0,
            WC_PKCS12_ITT_DEFAULT, &rng, NULL);
    \endcode

    \sa wc_GetPkcs8TraditionalOffset
    \sa wc_CreatePKCS8Key
    \sa wc_DecryptPKCS8Key
    \sa wc_CreateEncryptedPKCS8Key
*/
int wc_EncryptPKCS8Key(byte* key, word32 keySz, byte* out,
        word32* outSz, const char* password, int passwordSz, int vPKCS,
        int pbeOid, int encAlgId, byte* salt, word32 saltSz, int itt,
        WC_RNG* rng, void* heap);

/*!
    \ingroup ASN

    \brief この関数は暗号化されたPKCS#8のDER形式の鍵を受け取り、復号してPKCS#8 DER形式に変換します。
     wc_EncryptPKCS8Keyによって行われた暗号化を元に戻します。RFC5208を参照してください。
     入力データは復号データによって上書きされます。

    \return 成功時には復号データの長さを返します。
    \return エラー発生時には負の整数値を返します。

    \param input 入力時には暗号化されたPKCS#8鍵データを含みます。出力時には復号されたPKCS#8鍵データを含みます。
    \param sz 入力バッファのサイズ
    \param password 鍵を暗号化する際のパスワード
    \param passwordSz パスワードのサイズ(NULL終端文字は含まない)

    _Example_
    \code
    byte* pkcs8Enc;       // Encrypted PKCS#8 key made with wc_EncryptPKCS8Key.
    word32 pkcs8EncSz;    // Size of pkcs8Enc.
    const char* password; // Password to use for decryption.
    int passwordSz;       // Length of password (not including NULL terminator).

    ret = wc_DecryptPKCS8Key(pkcs8Enc, pkcs8EncSz, password, passwordSz);
    \endcode

    \sa wc_GetPkcs8TraditionalOffset
    \sa wc_CreatePKCS8Key
    \sa wc_EncryptPKCS8Key
    \sa wc_CreateEncryptedPKCS8Key
*/
int wc_DecryptPKCS8Key(byte* input, word32 sz, const char* password,
        int passwordSz);

/*!
    \ingroup ASN

    \brief この関数は従来のDER形式の鍵をPKCS#8フォーマットに変換し、暗号化を行います。
     この処理にはwc_CreatePKCS8Keyとwc_EncryptPKCS8Keyを使用します。

    \return 成功時には出力した暗号化鍵のサイズを返します。
    \return LENGTH_ONLY_E もし出力用バッファoutにNULLが渡された場合に返されます。その際にはoutSz変数に必要な出力用バッファサイズを格納します。
    \return エラー発生時には負の整数値を返します。

    \param key 従来のDER形式の鍵を含んだバッファへのポインタ
    \param keySz 鍵を含んだバッファのサイズ
    \param out 結果を出力する先のバッファへのポインタ。NULLが指定された場合には、必要なバッファサイズがoutSzに格納されます。
    \param outSz 結果を出力する先のバッファのサイズ
    \param password パスワードベース暗号アルゴリズムに使用されるパスワード
    \param passwordSz パスワードのサイズ(NULL終端文字は含まない)
    \param vPKCS 使用するPKCSのバージョン番号。1 はPKCS12 かPKCS5。
    \param pbeOid パスワードベース暗号化スキームのOID(PBES2 あるいはRFC2898 A.3にあるOIDの一つ)
    \param encAlgId 暗号化アルゴリズムID(例えばAES256CBCb)。
    \param salt ソルト。NULLの場合はランダムに選定したソルトが使用されます。
    \param saltSz ソルトサイズ。saltにNULLを渡した場合には0を指定できます。
    \param itt 鍵導出のための繰り返し回数
    \param rng 初期化済みのWC_RNG構造体へのポインタ
    \param heap 動的メモリ確保のためのヒープ。NULL指定も可。

    _Example_
    \code
    byte* key;            // Traditional private key (DER formatted).
    word32 keySz;         // Size of key.
    byte* pkcs8Enc;       // Encrypted PKCS#8 key.
    word32 pkcs8EncSz;    // Size of pkcs8Enc.
    const char* password; // Password to use for encryption.
    int passwordSz;       // Length of password (not including NULL terminator).
    WC_RNG rng;

    // The following produces an encrypted, PKCS#8 version of key in pkcs8Enc.
    // The encryption uses password-based encryption scheme 2 (PBE2) from PKCS#5
    // and the AES cipher in CBC mode with a 256-bit key. See RFC 8018 for more
    // on PKCS#5.
    ret = wc_CreateEncryptedPKCS8Key(key, keySz, pkcs8Enc, &pkcs8EncSz,
            password, passwordSz, PKCS5, PBES2, AES256CBCb, NULL, 0,
            WC_PKCS12_ITT_DEFAULT, &rng, NULL);
    \endcode

    \sa wc_GetPkcs8TraditionalOffset
    \sa wc_CreatePKCS8Key
    \sa wc_EncryptPKCS8Key
    \sa wc_DecryptPKCS8Key
*/
int wc_CreateEncryptedPKCS8Key(byte* key, word32 keySz, byte* out,
        word32* outSz, const char* password, int passwordSz, int vPKCS,
        int pbeOid, int encAlgId, byte* salt, word32 saltSz, int itt,
        WC_RNG* rng, void* heap);

/*!
    \ingroup ASN

    \brief この関数はcert引数で与えられたDecodedCert構造体を初期化します。
     DER形式の証明書を含んでいるsource引数の指すポインタから証明書サイズinSzの長さを内部に保存します。
     この関数の後に呼び出されるwc_ParseCertによって証明書が解析されます。

    \param cert DecodedCert構造体へのポインタ
    \param source DER形式の証明書データへのポインタ
    \param inSz 証明書データのサイズ（バイト数）
    \param heap 動的メモリ確保のためのヒープ。NULL指定も可。

    _Example_
    \code
    DecodedCert decodedCert; // Decoded certificate object.
    byte* certBuf;           // DER-encoded certificate buffer.
    word32 certBufSz;        // Size of certBuf in bytes.

    wc_InitDecodedCert(&decodedCert, certBuf, certBufSz, NULL);
    \endcode

    \sa wc_ParseCert
    \sa wc_FreeDecodedCert
*/
void wc_InitDecodedCert(struct DecodedCert* cert,
    const byte* source, word32 inSz, void* heap);

/*!
    \ingroup ASN

    \brief この関数はDecodedCert構造体に保存されているDER形式の証明書を解析し、その構造体に各種フィールドを設定します。
    DecodedCert構造体はwc_InitDecodedCertを呼び出して初期化しておく必要があります。
    この関数はオプションでCertificateManager構造体へのポインタを受け取り、CAが証明書マネジャーで検索できた場合には、
    そのCAに関する情報もDecodedCert構造体に追加設定します。

    \return 0 成功時に返します。
    \return エラー発生時には負の整数値を返します。

    \param cert 初期化済みのDecodedCert構造体へのポインタ。
    \param type 証明書タイプ。タイプの設定値についてはasn_public.hのCertType enum定義を参照してください。
    \param verify 呼び出し側が証明書の検証を求めていることを指示すフラグです。
    \param cm CertificateManager構造体へのポインタ。オプションで指定可。NULLでも可。

    _Example_
    \code
    int ret;
    DecodedCert decodedCert; // Decoded certificate object.
    byte* certBuf;           // DER-encoded certificate buffer.
    word32 certBufSz;        // Size of certBuf in bytes.

    wc_InitDecodedCert(&decodedCert, certBuf, certBufSz, NULL);
    ret = wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        fprintf(stderr, "wc_ParseCert failed.\n");
    }
    \endcode

    \sa wc_InitDecodedCert
    \sa wc_FreeDecodedCert
*/
int wc_ParseCert(DecodedCert* cert, int type, int verify, void* cm);

/*!
    \ingroup ASN

    \brief この関数はwc_InitDecodedCertで初期化済みのDecodedCert構造体を解放します。

    \param cert 初期化済みのDecodedCert構造体へのポインタ。

    _Example_
    \code
    int ret;
    DecodedCert decodedCert; // Decoded certificate object.
    byte* certBuf;           // DER-encoded certificate buffer.
    word32 certBufSz;        // Size of certBuf in bytes.

    wc_InitDecodedCert(&decodedCert, certBuf, certBufSz, NULL);
    ret = wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        fprintf(stderr, "wc_ParseCert failed.\n");
    }
    wc_FreeDecodedCert(&decodedCert);
    \endcode

    \sa wc_InitDecodedCert
    \sa wc_ParseCert
*/
void wc_FreeDecodedCert(struct DecodedCert* cert);

/*!
    \ingroup ASN

    \brief この関数はタイムコールバック関数を登録します。wolfSSLが現在時刻を必要としたタイミングでこのコールバックを呼び出します。
    このタイムコールバック関数のプロトタイプ（シグネチャ）はC標準ライブラリの"time"関数と同一です。


    \return 0 成功時に返します。

    \param f タイムコールバック関数ポインタ

    _Example_
    \code
    int ret = 0;
    // Time callback prototype
    time_t my_time_cb(time_t* t);
    // Register it
    ret = wc_SetTimeCb(my_time_cb);
    if (ret != 0) {
        // failed to set time callback
    }
    time_t my_time_cb(time_t* t)
    {
        // custom time function
    }
    \endcode

    \sa wc_Time
*/
int wc_SetTimeCb(wc_time_cb f);

/*!
    \ingroup ASN

    \brief この関数は現在時刻を取得します。デフォルトでXTIMEマクロ関数を使います。このマクロ関数はプラットフォーム依存です。
    ユーザーはこのマクロの代わりにwc_SetTimeCbでタイムコールバック関数を使うように設定することができます

    \return 成功時には現在時刻を返します。

    \param t 現在時刻を返却するオプションのtime_t型変数。

    _Example_
    \code
    time_t currentTime = 0;
    currentTime = wc_Time(NULL);
    wc_Time(&currentTime);
    \endcode

    \sa wc_SetTimeCb
*/
time_t wc_Time(time_t* t);

/*!
    \ingroup ASN

    \brief この関数はX.509証明書にカスタム拡張を追加します。
    注: この関数に渡すポインタ引数が保持する内容は証明書が生成されるまで変更されてはいけません。
    この関数ではポインタが指す先の内容は別のバッファには複製しません。

    \return 0 成功時に返します。
    \return エラー発生時には負の整数値を返します。

    \param cert 初期化済みのDecodedCert構造体へのポインタ。
    \param critical 0が指定された場合には追加する拡張はクリティカルとはマークされません。
     0以外が指定された場合にはクリティカルとマークされます。
    \param oid ドット区切りのoid文字列。例えば、"1.2.840.10045.3.1.7"
    \param der 拡張情報のDERエンコードされた内容を含むバッファへのポインタ。
    \param derSz DERエンコードされた内容を含むバッファのサイズ


    _Example_
    \code
    int ret = 0;
    Cert newCert;
    wc_InitCert(&newCert);

    // Code to setup subject, public key, issuer, and other things goes here.

    ret = wc_SetCustomExtension(&newCert, 1, "1.2.3.4.5",
              (const byte *)"This is a critical extension", 28);
    if (ret < 0) {
        // Failed to set the extension.
    }

    ret = wc_SetCustomExtension(&newCert, 0, "1.2.3.4.6",
              (const byte *)"This is NOT a critical extension", 32)
    if (ret < 0) {
        // Failed to set the extension.
    }

    // Code to sign the certificate and then write it out goes here.

    \endcode

    \sa wc_InitCert
    \sa wc_SetUnknownExtCallback
*/
int wc_SetCustomExtension(Cert *cert, int critical, const char *oid,
                                      const byte *der, word32 derSz);

/*!
    \ingroup ASN

    \brief この関数はwolfSSLが証明書の解析中に未知のX.509拡張に遭遇した際に呼び出すコールバック関数を登録します。
    コールバック関数のプロトタイプは使用例を参照してください。

    \return 0 成功時に返します。
    \return エラー発生時には負の整数値を返します。

    \param cert コールバック関数を登録する対象のDecodedCert構造体へのポインタ。
    \param cb 登録されるコールバック関数ポインタ

    _Example_
    \code
    int ret = 0;
    // Unknown extension callback prototype
    int myUnknownExtCallback(const word16* oid, word32 oidSz, int crit,
                             const unsigned char* der, word32 derSz);

    // Register it
    ret = wc_SetUnknownExtCallback(cert, myUnknownExtCallback);
    if (ret != 0) {
        // failed to set the callback
    }

    // oid: OIDを構成するドット区切りの数を格納した配列
    // oidSz: oid内の値の数
    // crit: 拡張がクリティカルとマークされているか
    // der: DERエンコードされている拡張の内容
    // derSz: 拡張の内容のサイズ
    int myCustomExtCallback(const word16* oid, word32 oidSz, int crit,
                            const unsigned char* der, word32 derSz) {

        // 拡張を解析するロジックはここに記述します

        // NOTE: コールバック関数から0を返すとwolfSSLに対してこの拡張を受け入れ可能と
        // 表明することになります。この拡張を処理できると判断できない場合にはエラーを
        // 返してください。クリティカルとマークされている未知の拡張に遭遇した際の標準的
        // な振る舞いはASN_CRIT_EXT_Eを返すことです。
        // 簡潔にするためにこの例ではすべての拡張情報を受け入れ可としていますが、実際には実情に沿うようにロジックを追加してください。

        return 0;
    }
    \endcode

    \sa ParseCert
    \sa wc_SetCustomExtension
*/
int wc_SetUnknownExtCallback(DecodedCert* cert,
                                             wc_UnknownExtCallback cb);
/*!
    \ingroup ASN

    \brief この関数はDER形式のX.509 証明書の署名を与えられた公開鍵を使って検証します。
    公開鍵はDER形式で全公開鍵情報を含んだものが求められます。

    \return 0 成功時に返します。
    \return エラー発生時には負の整数値を返します。

    \param cert DER形式のX.509証明書を含んだバッファへのポインタ
    \param certSz 証明書を含んだバッファのサイズ
    \param heap 動的メモリ確保のためのヒープ。NULL指定も可。
    \param pubKey DER形式の公開鍵を含んだバッファへのポインタ
    \param pubKeySz 公開鍵を含んだバッファのサイズ
    \param pubKeyOID 公開鍵のアルゴリズムを特定するOID(すなわち: ECDSAk, DSAk や RSAk)
*/
int wc_CheckCertSigPubKey(const byte* cert, word32 certSz,
                                      void* heap, const byte* pubKey,
                                      word32 pubKeySz, int pubKeyOID);

/*!
    \ingroup ASN

    \brief この関数はAsn1PrintOptions構造体を初期化します。

    \return  0 成功時に返します。
    \return  BAD_FUNC_ARG asn1がNULLの場合に返されます。

    \param opts  プリントのためのAsn1PrintOptions構造体へのポインタ

    _Example_
    \code
    Asn1PrintOptions opt;

    // Initialize ASN.1 print options before use.
    wc_Asn1PrintOptions_Init(&opt);
    \endcode

    \sa wc_Asn1PrintOptions_Set
    \sa wc_Asn1_PrintAll
*/
int wc_Asn1PrintOptions_Init(Asn1PrintOptions* opts);

/*!
    \ingroup ASN

    \brief この関数はAsn1PrintOptions構造体にプリント情報を設定します。

    \return  0 成功時に返します。
    \return  BAD_FUNC_ARG asn1がNULLの場合に返されます。
    \return  BAD_FUNC_ARG valが範囲外の場合に返されます。

    \param opts  Asn1PrintOptions構造体へのポインタ
    \param opt   設定する情報へのポインタ
    \param val   設定値

    _Example_
    \code
    Asn1PrintOptions opt;

    // Initialize ASN.1 print options before use.
    wc_Asn1PrintOptions_Init(&opt);
    // Set the number of indents when printing tag name to be 1.
    wc_Asn1PrintOptions_Set(&opt, ASN1_PRINT_OPT_INDENT, 1);
    \endcode

    \sa wc_Asn1PrintOptions_Init
    \sa wc_Asn1_PrintAll
*/
int wc_Asn1PrintOptions_Set(Asn1PrintOptions* opts, enum Asn1PrintOpt opt,
    word32 val);

/*!
    \ingroup ASN

    \brief この関数はAsn1構造体を初期化します。

    \return  0 成功時に返します。
    \return  BAD_FUNC_ARG asn1がNULLの場合に返されます。

    \param asn1  Asn1構造体へのポインタ

    _Example_
    \code
    Asn1 asn1;

    // Initialize ASN.1 parse object before use.
    wc_Asn1_Init(&asn1);
    \endcode

    \sa wc_Asn1_SetFile
    \sa wc_Asn1_PrintAll
 */
int wc_Asn1_Init(Asn1* asn1);

/*!
    \ingroup ASN

    \brief この関数は出力先として使用するファイルをAsn1構造体にセットします。

    \return  0 成功時に返します。
    \return  BAD_FUNC_ARG asn1がNULLの場合に返されます。
    \return  BAD_FUNC_ARG fileがXBADFILEの場合に返されます。.

    \param asn1  Asn1構造体へのポインタ
    \param file  プリント先のファイル

    _Example_
    \code
    Asn1 asn1;

    // Initialize ASN.1 parse object before use.
    wc_Asn1_Init(&asn1);
    // Set standard out to be the file descriptor to write to.
    wc_Asn1_SetFile(&asn1, stdout);
    \endcode

    \sa wc_Asn1_Init
    \sa wc_Asn1_PrintAll
 */
int wc_Asn1_SetFile(Asn1* asn1, XFILE file);

/*!
    \ingroup ASN

    \brief ASN.1アイテムをプリントします。

    \return  0 成功時に返します。
    \return  BAD_FUNC_ARG asn1かoptsがNULLの場合に返されます。
    \return  ASN_LEN_E ASN.1アイテムが長すぎる場合に返されます。
    \return  ASN_DEPTH_E 終了オフセットが無効の場合に返されます。
    \return  ASN_PARSE_E 全のASN.1アイテムの解析が完了できなかった場合に返されます。

    \param asn1  Asn1構造体へのポインタ
    \param opts  Asn1PrintOptions構造体へのポインタ
    \param data  BER/DER形式のプリント対象データへのポインタ
    \param len   プリント対象データのサイズ（バイト数）

    \code
    Asn1PrintOptions opts;
    Asn1 asn1;
    unsigned char data[] = { Initialize with DER/BER data };
    word32 len = sizeof(data);

    // Initialize ASN.1 print options before use.
    wc_Asn1PrintOptions_Init(&opt);
    // Set the number of indents when printing tag name to be 1.
    wc_Asn1PrintOptions_Set(&opt, ASN1_PRINT_OPT_INDENT, 1);

    // Initialize ASN.1 parse object before use.
    wc_Asn1_Init(&asn1);
    // Set standard out to be the file descriptor to write to.
    wc_Asn1_SetFile(&asn1, stdout);
    // Print all ASN.1 items in buffer with the specified print options.
    wc_Asn1_PrintAll(&asn1, &opts, data, len);
    \endcode

    \sa wc_Asn1_Init
    \sa wc_Asn1_SetFile
 */
int wc_Asn1_PrintAll(Asn1* asn1, Asn1PrintOptions* opts, unsigned char* data,
    word32 len);

