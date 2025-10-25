/*!
    \ingroup ASN

    \brief この関数は、デフォルトのオプションでデフォルトの証明書を初期化します：
    version = 3（0x2）、serial = 0、sigType = SHA_WITH_RSA、issuer = 空白、
    daysValid = 500、selfSigned = 1（true）発行者としてsubjectを使用、
    subject = 空白

    \return none 返り値なし。

    \param cert 初期化する未初期化のcert構造体へのポインタ

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

     \brief この関数は、証明書操作中に使用するための新しいCert構造体を割り当てます。アプリケーションが構造体自体を割り当てる必要はありません。Cert構造体もこの関数によって初期化されるため、wc_InitCert()を呼び出す必要がなくなります。アプリケーションが割り当てられたCert構造体の使用を終了したら、wc_CertFree()を呼び出す必要があります。

     \return pointer 成功した場合、呼び出しは新しく割り当てられ初期化されたCertへのポインタを返します。
     \return NULL メモリ割り当て失敗時。

     \param A 動的割り当てに使用されるヒープへのポインタ。NULLでも可。

     _Example_
     \code
     Cert*   myCert;

     myCert = wc_CertNew(NULL);
     if (myCert == NULL) {
         // Cert作成失敗
     }
     \endcode

     \sa wc_InitCert
     \sa wc_MakeCert
     \sa wc_CertFree

*/
Cert* wc_CertNew(void* heap);

/*!
     \ingroup ASN

     \brief この関数は、wc_CertNew()への以前の呼び出しによってcert構造体に割り当てられたメモリを解放します。

     \return None.

     \param A 解放するcert構造体へのポインタ。

     _Example_
     \code
     Cert*   myCert;

     myCert = wc_CertNew(NULL);

     // 証明書操作を実行。

     wc_CertFree(myCert);
     \endcode

     \sa wc_InitCert
     \sa wc_MakeCert
     \sa wc_CertNew

*/
void  wc_CertFree(Cert* cert);

/*!
    \ingroup ASN

    \brief CA署名付き証明書を作成するために使用されます。subject情報が入力された後に呼び出されます。この関数は、cert入力からx509証明書v3 RSAまたはECCを作成します。次に、この証明書をderBufferに書き込みます。証明書を生成するために、rsaKeyまたはeccKeyのいずれかを受け取ります。このメソッドを呼び出す前に、証明書をwc_InitCertで初期化する必要があります。

    \return Success 指定された入力certからx509証明書を正常に作成すると、生成された証明書のサイズを返します。
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return BUFFER_E 提供されたderBufferが生成された証明書を格納するには小さすぎる場合に返されます
    \return Others 証明書の生成が成功しない場合、追加のエラーメッセージが返される可能性があります。

    \param cert 初期化されたcert構造体へのポインタ
    \param derBuffer 生成された証明書を保持するバッファへのポインタ
    \param derSz 証明書を格納するバッファのサイズ
    \param rsaKey 証明書の生成に使用されるrsaキーを含むRsaKey構造体へのポインタ
    \param eccKey 証明書の生成に使用されるeccキーを含むEccKey構造体へのポインタ
    \param rng 証明書を作成するために使用される乱数生成器へのポインタ

    _Example_
    \code
    Cert myCert;
    wc_InitCert(&myCert);
    WC_RNG rng;
    // rngを初期化;
    RsaKey key;
    // keyを初期化;
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

    \brief この関数は、入力証明書を使用して証明書署名要求を作成し、出力をderBufferに書き込みます。証明書要求を生成するために、rsaKeyまたはeccKeyのいずれかを受け取ります。証明書署名要求に署名するには、この関数の後にwc_SignCert()を呼び出す必要があります。この関数の使用例については、wolfCryptテストアプリケーション（./wolfcrypt/test/test.c）を参照してください。

    \return Success 指定された入力certからX.509証明書要求を正常に作成すると、生成された証明書要求のサイズを返します。
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return BUFFER_E 提供されたderBufferが生成された証明書を格納するには小さすぎる場合に返されます
    \return Other 証明書要求の生成が成功しない場合、追加のエラーメッセージが返される可能性があります。

    \param cert 初期化されたcert構造体へのポインタ
    \param derBuffer 生成された証明書要求を保持するバッファへのポインタ
    \param derSz 証明書要求を格納するバッファのサイズ
    \param rsaKey 証明書要求の生成に使用されるrsaキーを含むRsaKey構造体へのポインタ
    \param eccKey 証明書要求の生成に使用されるeccキーを含むEccKey構造体へのポインタ

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    EccKey key;
    // keyを初期化;
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

    \brief この関数はbufferに署名し、署名をbufferの末尾に追加します。署名タイプを受け取ります。CA署名付き証明書を作成する場合は、wc_MakeCert()またはwc_MakeCertReq()の後に呼び出す必要があります。

    \return Success 証明書の署名に成功すると、証明書の新しいサイズ（署名を含む）を返します。
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return BUFFER_E 提供されたバッファが生成された証明書を格納するには小さすぎる場合に返されます
    \return Other 証明書の生成が成功しない場合、追加のエラーメッセージが返される可能性があります。

    \param requestSz 署名を要求している証明書本文のサイズ
    \param sType 作成する署名のタイプ。有効なオプションは：CTC_MD5wRSA、CTC_SHAwRSA、CTC_SHAwECDSA、CTC_SHA256wECDSA、およびCTC_SHA256wRSA
    \param buffer 署名される証明書を含むバッファへのポインタ。成功時：新しく署名された証明書を保持します
    \param buffSz 新しく署名された証明書を格納するバッファの（合計）サイズ
    \param rsaKey 証明書に署名するために使用されるrsaキーを含むRsaKey構造体へのポインタ
    \param eccKey 証明書に署名するために使用されるeccキーを含むEccKey構造体へのポインタ
    \param rng 証明書に署名するために使用される乱数生成器へのポインタ

    _Example_
    \code
    Cert myCert;
    byte* derCert = (byte*)malloc(FOURK_BUF);
    // myCert、derCertを初期化
    RsaKey key;
    // keyを初期化;
    WC_RNG rng;
    // rngを初期化

    word32 certSz;
    certSz = wc_SignCert(myCert.bodySz, myCert.sigType,derCert,FOURK_BUF,
    &key, NULL,
    &rng);
    \endcode

    \sa wc_InitCert
    \sa wc_MakeCert
*/
int  wc_SignCert(int requestSz, int sigType, byte* derBuffer,
                 word32 derSz, RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng);

/*!
    \ingroup ASN

    \brief この関数は、自己署名用の前の2つの関数、wc_MakeCertとwc_SignCertの組み合わせです（前の関数はCA要求に使用できます）。証明書を作成してから署名し、自己署名証明書を生成します。

    \return Success 証明書の署名に成功すると、証明書の新しいサイズを返します。
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return BUFFER_E 提供されたバッファが生成された証明書を格納するには小さすぎる場合に返されます
    \return Other 証明書の生成が成功しない場合、追加のエラーメッセージが返される可能性があります。

    \param cert 作成して署名する証明書へのポインタ
    \param buffer 署名された証明書を保持するバッファへのポインタ
    \param buffSz 署名された証明書を格納するバッファのサイズ
    \param key 証明書に署名するために使用されるrsaキーを含むRsaKey構造体へのポインタ
    \param rng 証明書の生成と署名に使用される乱数生成器へのポインタ

    _Example_
    \code
    Cert myCert;
    byte* derCert = (byte*)malloc(FOURK_BUF);
    // myCert、derCertを初期化
    RsaKey key;
    // keyを初期化;
    WC_RNG rng;
    // rngを初期化

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

    \brief この関数は、証明書の発行者を、提供されたpem issuerFileの発行者に設定します。また、証明書の自己署名属性をfalseに変更します。issuerFileで指定された発行者は、cert発行者を設定する前に検証されます。このメソッドは、署名前にフィールドを設定するために使用されます。

    \return 0 証明書の発行者を正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 発行者を設定する証明書へのポインタ
    \param issuerFile pem形式の証明書を含むファイルのパス

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    if(wc_SetIssuer(&myCert, "./path/to/ca-cert.pem") != 0) {
    	// 発行者設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubject
    \sa wc_SetIssuerBuffer
*/
int  wc_SetIssuer(Cert* cert, const char* issuerFile);

/*!
    \ingroup ASN

    \brief この関数は、証明書のsubjectを、提供されたpem subjectFileのsubjectに設定します。このメソッドは、署名前にフィールドを設定するために使用されます。

    \return 0 証明書の発行者を正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 発行者を設定する証明書へのポインタ
    \param subjectFile pem形式の証明書を含むファイルのパス

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    if(wc_SetSubject(&myCert, "./path/to/ca-cert.pem") != 0) {
    	// subject設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetSubject(Cert* cert, const char* subjectFile);


/*!
    \ingroup ASN

    \brief この関数は、提供されたderバッファのsubjectから証明書の生のsubjectを設定します。このメソッドは、署名前に生のsubjectフィールドを設定するために使用されます。
    \return 0 証明書のsubjectを正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 生のsubjectを設定する証明書へのポインタ
    \param der subjectを取得するder形式の証明書を含むバッファへのポインタ
    \param derSz subjectを取得するder形式の証明書を含むバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // derを初期化
    if(wc_SetSubjectRaw(&myCert, der, FOURK_BUF) != 0) {
        // subject設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubject
*/
int  wc_SetSubjectRaw(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数は、証明書構造体から生のsubjectを取得します。

    \return 0 証明書からsubjectを正常に取得した場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます

    \param subjectRaw 正常に返された場合の生のsubjectへのポインタのポインタ
    \param cert 生のsubjectを取得する証明書へのポインタ

    _Example_
    \code
    Cert myCert;
    byte *subjRaw;
    // myCertを初期化

    if(wc_GetSubjectRaw(&subjRaw, &myCert) != 0) {
        // subject設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubjectRaw
*/
int  wc_GetSubjectRaw(byte **subjectRaw, Cert *cert);

/*!
    \ingroup ASN

    \brief この関数は、証明書の代替名を、提供されたpemファイル内の代替名に設定します。これは、同じ証明書で複数のドメインを保護したい場合に便利です。このメソッドは、署名前にフィールドを設定するために使用されます。

    \return 0 証明書の代替名を正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 代替名を設定する証明書へのポインタ
    \param file pem形式の証明書を含むファイルのパス

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    if(wc_SetSubject(&myCert, "./path/to/ca-cert.pem") != 0) {
    	// 代替名設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetAltNames(Cert* cert, const char* file);

/*!
    \ingroup ASN

    \brief この関数は、提供されたderバッファの発行者から証明書の発行者を設定します。また、証明書の自己署名属性をfalseに変更します。このメソッドは、署名前にフィールドを設定するために使用されます。

    \return 0 証明書の発行者を正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 発行者を設定する証明書へのポインタ
    \param der 発行者を取得するder形式の証明書を含むバッファへのポインタ
    \param derSz 発行者を取得するder形式の証明書を含むバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // derを初期化
    if(wc_SetIssuerBuffer(&myCert, der, FOURK_BUF) != 0) {
	    // issuer設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetIssuerBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数は、提供されたderバッファの発行者から証明書の生の発行者を設定します。このメソッドは、署名前に生の発行者フィールドを設定するために使用されます。

    \return 0 証明書の発行者を正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 生の発行者を設定する証明書へのポインタ
    \param der subjectを取得するder形式の証明書を含むバッファへのポインタ
    \param derSz subjectを取得するder形式の証明書を含むバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // derを初期化
    if(wc_SetIssuerRaw(&myCert, der, FOURK_BUF) != 0) {
        // subject設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetIssuer
*/
int  wc_SetIssuerRaw(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数は、提供されたderバッファのsubjectから証明書のsubjectを設定します。このメソッドは、署名前にフィールドを設定するために使用されます。

    \return 0 証明書のsubjectを正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert subjectを設定する証明書へのポインタ
    \param der subjectを取得するder形式の証明書を含むバッファへのポインタ
    \param derSz subjectを取得するder形式の証明書を含むバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // derを初期化
    if(wc_SetSubjectBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// subject設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetSubject
*/
int  wc_SetSubjectBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数は、提供されたderバッファの代替名から証明書の代替名を設定します。これは、同じ証明書で複数のドメインを保護したい場合に便利です。このメソッドは、署名前にフィールドを設定するために使用されます。

    \return 0 証明書の代替名を正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 代替名を設定する証明書へのポインタ
    \param der 代替名を取得するder形式の証明書を含むバッファへのポインタ
    \param derSz 代替名を取得するder形式の証明書を含むバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // derを初期化
    if(wc_SetAltNamesBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// subject設定エラー
    }
    \endcode

    \sa wc_InitCert
    \sa wc_SetAltNames
*/
int  wc_SetAltNamesBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief この関数は、提供されたderバッファの日付範囲から証明書の日付を設定します。このメソッドは、署名前にフィールドを設定するために使用されます。

    \return 0 証明書の日付を正常に設定した場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_PARSE_E 証明書ヘッダーファイルの解析エラーがある場合に返されます
    \return ASN_OBJECT_ID_E 証明書から暗号化タイプを解析する際にエラーがある場合に返されます
    \return ASN_EXPECT_0_E 証明書ファイルの暗号化仕様にフォーマットエラーがある場合に返されます
    \return ASN_BEFORE_DATE_E 日付が証明書の開始日より前の場合に返されます
    \return ASN_AFTER_DATE_E 日付が証明書の有効期限より後の場合に返されます
    \return ASN_BITSTR_E 証明書からビット文字列を解析する際にエラーがある場合に返されます
    \return ECC_CURVE_OID_E 証明書からECCキーを解析する際にエラーがある場合に返されます
    \return ASN_UNKNOWN_OID_E 証明書が不明なキーオブジェクトIDを使用している場合に返されます
    \return ASN_VERSION_E ALLOW_V1_EXTENSIONSオプションが定義されておらず、証明書がV1またはV2証明書の場合に返されます
    \return BAD_FUNC_ARG 証明書拡張の処理エラーがある場合に返されます
    \return ASN_CRIT_EXT_E 証明書の処理中に見慣れない重要な拡張に遭遇した場合に返されます
    \return ASN_SIG_OID_E 署名暗号化タイプが提供されたファイル内の証明書の暗号化タイプと同じでない場合に返されます
    \return ASN_SIG_CONFIRM_E 証明書署名の確認が失敗した場合に返されます
    \return ASN_NAME_INVALID_E 証明書の名前がCA名前制約で許可されていない場合に返されます
    \return ASN_NO_SIGNER_E 証明書の真正性を検証するCA署名者がいない場合に返されます

    \param cert 日付を設定する証明書へのポインタ
    \param der 日付範囲を取得するder形式の証明書を含むバッファへのポインタ
    \param derSz 日付範囲を取得するder形式の証明書を含むバッファのサイズ

    _Example_
    \code
    Cert myCert;
    // myCertを初期化
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // derを初期化
    if(wc_SetDatesBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// subject設定エラー
    }
    \endcode

    \sa wc_InitCert
*/
int  wc_SetDatesBuffer(Cert* cert, const byte* der, int derSz);

/*!
    \ingroup ASN

    \brief RSAまたはECC公開鍵からAKIDを設定します。注：rsakeyまたはeckeyのいずれか一方のみを設定し、両方は設定しないでください。

    \return 0 成功
    \return BAD_FUNC_ARG certがnullまたはrsakeyとeckeyの両方がnullの場合。
    \return MEMORY_E メモリの割り当てエラー。
    \return PUBLIC_KEY_E キーへの書き込みエラー。

    \param cert SKIDを設定する証明書へのポインタ。
    \param rsakey 読み取り元のRsaKey構造体へのポインタ。
    \param eckey 読み取り元のecc_keyへのポインタ。

    _Example_
    \code
    Cert myCert;
    RsaKey keypub;

    wc_InitRsaKey(&keypub, 0);

    if (wc_SetAuthKeyIdFromPublicKey(&myCert, &keypub, NULL) != 0)
    {
        // エラーを処理
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

    \brief DERエンコードされた証明書からAKIDを設定します。

    \return 0 成功
    \return BAD_FUNC_ARG いずれかの引数がnullまたはderSzが0未満の場合のエラー。
    \return MEMORY_E メモリの割り当てに問題がある場合のエラー。
    \return ASN_NO_SKID サブジェクトキーIDが見つかりません。

    \param cert 書き込み先のCert構造体。
    \param der DERエンコードされた証明書バッファ。
    \param derSz derのサイズ（バイト単位）。

    _Example_
    \code
    Cert some_cert;
    byte some_der[] = { // DERバッファを初期化 };
    wc_InitCert(&some_cert);
    if(wc_SetAuthKeyIdFromCert(&some_cert, some_der, sizeof(some_der) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_SetAuthKeyIdFromPublicKey
    \sa wc_SetAuthKeyId
*/
int wc_SetAuthKeyIdFromCert(Cert *cert, const byte *der, int derSz);

/*!
    \ingroup ASN

    \brief PEM形式の証明書ファイルからAKIDを設定します。

    \return 0 成功
    \return BAD_FUNC_ARG certまたはfileがnullの場合のエラー。
    \return MEMORY_E メモリの割り当てに問題がある場合のエラー。

    \param cert AKIDを設定したいCert構造体。
    \param file PEM証明書ファイルを含むバッファ。

    _Example_
    \code
    char* file_name = "/path/to/file";
    cert some_cert;
    wc_InitCert(&some_cert);

    if(wc_SetAuthKeyId(&some_cert, file_name) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_SetAuthKeyIdFromPublicKey
    \sa wc_SetAuthKeyIdFromCert
*/
int wc_SetAuthKeyId(Cert *cert, const char* file);

/*!
    \ingroup ASN

    \brief RSAまたはECC公開鍵からSKIDを設定します。

    \return 0 成功
    \return BAD_FUNC_ARG certまたはrsakeyとeckeyがnullの場合に返されます。
    \return MEMORY_E メモリの割り当てエラーがある場合に返されます。
    \return PUBLIC_KEY_E 公開鍵の取得エラーがある場合に返されます。

    \param cert 使用するCert構造体へのポインタ。
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
        // エラーを処理
    }
    \endcode

    \sa wc_SetSubjectKeyId
*/
int wc_SetSubjectKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey,
                                                ecc_key *eckey);

/*!
    \ingroup ASN

    \brief PEM形式の公開鍵ファイルからSKIDを設定します。両方の引数が必要です。

    \return 0 成功
    \return BAD_FUNC_ARG certまたはfileがnullの場合に返されます。
    \return MEMORY_E キー用のメモリ割り当てに問題がある場合に返されます。
    \return PUBLIC_KEY_E 公開鍵のデコードエラーがある場合に返されます。

    \param cert SKIDを設定するCert構造体。
    \param file PEMエンコードされたファイルを含む。

    _Example_
    \code
    const char* file_name = "path/to/file";
    Cert some_cert;
    wc_InitCert(&some_cert);

    if(wc_SetSubjectKeyId(&some_cert, file_name) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_SetSubjectKeyIdFromPublicKey
*/
int wc_SetSubjectKeyId(Cert *cert, const char* file);

/*!
    \ingroup RSA

    \brief この関数を使用すると、カンマ区切りのトークン文字列を使用してキー使用法を設定できます。受け入れられるトークンは：digitalSignature、nonRepudiation、contentCommitment、keyCertSign、cRLSign、dataEncipherment、keyAgreement、keyEncipherment、encipherOnly、decipherOnlyです。例："digitalSignature,nonRepudiation" nonRepudiationとcontentCommitmentは同じ用途です。

    \return 0 成功
    \return BAD_FUNC_ARG いずれかの引数がnullの場合に返されます。
    \return MEMORY_E メモリの割り当てエラーがある場合に返されます。
    \return KEYUSAGE_E 認識されないトークンが入力された場合に返されます。

    \param cert 初期化されたCert構造体へのポインタ。
    \param value 使用法を設定するトークンのカンマ区切り文字列。

    _Example_
    \code
    Cert cert;
    wc_InitCert(&cert);

    if(wc_SetKeyUsage(&cert, "cRLSign,keyCertSign") != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_InitCert
    \sa wc_MakeRsaKey
*/
int wc_SetKeyUsage(Cert *cert, const char *value);

/*!
    \ingroup ASN

    \brief ファイルからPEMキーを読み込み、DERエンコードされたバッファに変換します。

    \return 0 成功
    \return <0 エラー
    \return SSL_BAD_FILE ファイルを開く際に問題があります。
    \return MEMORY_E ファイルバッファ用のメモリ割り当てエラーがあります。
    \return BUFFER_E derBufが変換されたキーを保持するのに十分な大きさではありません。

    \param fileName ロードするファイルの名前。
    \param derBuf DERエンコードされたキー用のバッファ。
    \param derSz DERバッファのサイズ。

    _Example_
    \code
    char* some_file = "filename";
    unsigned char der[];

    if(wc_PemPubKeyToDer(some_file, der, sizeof(der)) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_PubKeyPemToDer
*/
int wc_PemPubKeyToDer(const char* fileName,
                                       unsigned char* derBuf, int derSz);

/*!
    \ingroup ASN

    \brief PEMエンコードされた公開鍵をDERに変換します。バッファに書き込まれたバイト数、またはエラーの場合は負の値を返します。

    \return >0 成功、書き込まれたバイト数。
    \return BAD_FUNC_ARG pem、buff、またはbuffSzがnullの場合に返されます
    \return <0 関数内でエラーが発生しました。

    \param pem PEMエンコードされたキー
    \param pemSz pemのサイズ
    \param buff 出力用バッファへのポインタ。
    \param buffSz バッファのサイズ。

    _Example_
    \code
    byte some_pem[] = { PEMキーで初期化 }
    unsigned char out_buffer[1024]; // バッファがDERを格納するのに十分な大きさであることを確認

    if(wc_PubKeyPemToDer(some_pem, sizeof(some_pem), out_buffer,
    sizeof(out_buffer)) < 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_PemPubKeyToDer
*/
int wc_PubKeyPemToDer(const unsigned char* pem, int pemSz,
                                      unsigned char* buff, int buffSz);

/*!
    \ingroup ASN

    \brief この関数は、pem証明書をder証明書に変換し、結果の証明書を提供されたderBufバッファに配置します。

    \return Success 成功時に生成されたderBufのサイズを返します
    \return BUFFER_E derBufのサイズが生成された証明書を保持するには小さすぎる場合に返されます
    \return MEMORY_E XMALLOCの呼び出しが失敗した場合に返されます

    \param fileName der証明書に変換するpem証明書を含むファイルへのパス
    \param derBuf 変換された証明書を格納するcharバッファへのポインタ
    \param derSz 変換された証明書を格納するcharバッファのサイズ

    _Example_
    \code
    char * file = "./certs/client-cert.pem";
    int derSz;
    byte* der = (byte*)XMALLOC((8*1024), NULL, DYNAMIC_TYPE_CERT);

    derSz = wc_PemCertToDer(file, der, (8*1024));
    if (derSz <= 0) {
        // PemCertToDerエラー
    }
    \endcode

    \sa なし
*/

int wc_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz);

/*!
    \ingroup ASN

    \brief この関数は、derバッファに含まれるder形式の入力証明書を、outputバッファに含まれるpem形式の出力証明書に変換します。これはインプレース変換ではなく、pem形式の出力を格納するために別のバッファを使用する必要があることに注意してください。

    \return Success 入力der証明書から正常にpem証明書を作成すると、生成されたpem証明書のサイズを返します。
    \return BAD_FUNC_ARG derファイルを解析してpemファイルとして格納する際にエラーがある場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_INPUT_E base64エンコードエラーの場合に返されます
    \return BUFFER_E 出力バッファがpem形式の証明書を格納するには小さすぎる場合に返される可能性があります

    \param der 変換する証明書のバッファへのポインタ
    \param derSz 変換する証明書のサイズ
    \param output pem形式の証明書を格納するバッファへのポインタ
    \param outSz pem形式の証明書を格納するバッファのサイズ
    \param type 生成する証明書のタイプ。有効なタイプは：CERT_TYPE、PRIVATEKEY_TYPE、ECC_PRIVATEKEY_TYPE、およびCERTREQ_TYPE。

    _Example_
    \code
    byte* der;
    // 証明書でderを初期化
    byte* pemFormatted[FOURK_BUF];

    word32 pemSz;
    pemSz = wc_DerToPem(der, derSz,pemFormatted,FOURK_BUF, CERT_TYPE);
    \endcode

    \sa wc_PemCertToDer
*/
int wc_DerToPem(const byte* der, word32 derSz, byte* output,
                                word32 outSz, int type);

/*!
    \ingroup ASN

    \brief この関数は、der形式の入力証明書を変換します、
    derバッファに含まれる、pem形式の出力証明書に変換し、outputバッファに格納します。これはインプレース変換ではなく、pem形式の出力を格納するために別のバッファを使用する必要があることに注意してください。暗号情報の設定を許可します。

    \return Success 入力der証明書から正常にpem証明書を作成すると、生成されたpem証明書のサイズを返します。
    \return BAD_FUNC_ARG derファイルを解析してpemファイルとして格納する際にエラーがある場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return ASN_INPUT_E base64エンコードエラーの場合に返されます
    \return BUFFER_E 出力バッファがpem形式の証明書を格納するには小さすぎる場合に返される可能性があります

    \param der 変換する証明書のバッファへのポインタ
    \param derSz 変換する証明書のサイズ
    \param output pem形式の証明書を格納するバッファへのポインタ
    \param outSz pem形式の証明書を格納するバッファのサイズ
    \param cipher_info 追加の暗号情報。
    \param type 生成する証明書のタイプ。有効なタイプは：CERT_TYPE、PRIVATEKEY_TYPE、ECC_PRIVATEKEY_TYPE、およびCERTREQ_TYPE。

    _Example_
    \code
    byte* der;
    // 証明書でderを初期化
    byte* pemFormatted[FOURK_BUF];

    word32 pemSz;
    byte* cipher_info[] { 追加の暗号情報。 }
    pemSz = wc_DerToPemEx(der, derSz, pemFormatted, FOURK_BUF, cipher_info, CERT_TYPE);
    \endcode

    \sa wc_PemCertToDer
*/
int wc_DerToPemEx(const byte* der, word32 derSz, byte* output,
                                word32 outSz, byte *cipher_info, int type);

/*!
    \ingroup CertsKeys

    \brief PEM形式のキーをDER形式に変換します。

    \return int 関数は正常実行時にバッファに書き込まれたバイト数を返します。
    \return int エラーを示す負の整数が返されます。

    \param pem PEMエンコードされた証明書へのポインタ。
    \param pemSz PEMバッファ（pem）のサイズ
    \param buff DerBuffer構造体のbufferメンバーのコピーへのポインタ。
    \param buffSz DerBuffer構造体に割り当てられたバッファスペースのサイズ。
    \param pass 関数に渡されるパスワード。

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
        // バイトがバッファに書き込まれました。
    }
    \endcode

    \sa wc_PemToDer
*/
int wc_KeyPemToDer(const unsigned char* pem, int pemSz,
                                    unsigned char* buff, int buffSz, const char* pass);

/*!
    \ingroup CertsKeys

    \brief この関数は、PEM形式の証明書をDER形式に変換します。OpenSSL関数PemToDerを呼び出します。

    \return buffer バッファに書き込まれたバイトを返します。

    \param pem PEM形式の証明書へのポインタ。
    \param pemSz 証明書のサイズ。
    \param buff DER形式にコピーされるバッファ。
    \param buffSz バッファのサイズ。
    \param type asn_public.h enum CertTypeにある証明書ファイルタイプ。

    _Example_
    \code
    const unsigned char* pem;
    int pemSz;
    unsigned char buff[BUFSIZE];
    int buffSz = sizeof(buff)/sizeof(char);
    int type;
    ...
    if(wc_CertPemToDer(pem, pemSz, buff, buffSz, type) <= 0) {
        // バッファにバイトが書き込まれました
    }
    \endcode

    \sa wc_PemToDer
*/
int wc_CertPemToDer(const unsigned char* pem, int pemSz,
                    unsigned char* buff, int buffSz, int type);

/*!
    \ingroup CertsKeys

    \brief この関数は、入力されたDecodedCert構造体からDER形式の公開鍵を取得します。このAPIを呼び出す前に、ユーザーはwc_InitDecodedCert()とwc_ParseCert()を呼び出す必要があります。wc_InitDecodedCert()はDER/ASN.1エンコードされた証明書を受け入れます。PEM証明書をDERに変換するには、wc_InitDecodedCert()を呼び出す前にまずwc_CertPemToDer()を使用してください。

    \return 0 成功時、エラー時は負の値。derKeyがNULLで長さのみを返す場合はLENGTH_ONLY_E。

    \param cert X.509証明書を保持する入力されたDecodedCert構造体
    \param derKey DERエンコードされた公開鍵を配置する出力バッファ
    \param derKeySz [IN/OUT] 入力時のderKeyバッファのサイズ、返却時の公開鍵のサイズ。derKeyがNULLとして渡された場合、derKeySzは公開鍵に必要なバッファサイズに設定され、関数からLENGTH_ONLY_Eが返されます。

    \sa wc_GetPubKeyDerFromCert
*/
int wc_GetPubKeyDerFromCert(struct DecodedCert* cert,
                                        byte* derKey, word32* derKeySz);

/*!
    \ingroup ASN

    \brief この関数は、入力バッファinputからECC秘密鍵を読み取り、秘密鍵を解析し、それを使用してecc_keyオブジェクトを生成し、keyに格納します。

    \return 0 秘密鍵のデコードに成功し、結果をecc_key構造体に格納した場合
    \return ASN_PARSE_E derファイルを解析してpemファイルとして格納する際にエラーがある場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return BUFFER_E 変換する証明書が指定された最大証明書サイズより大きい場合に返されます
    \return ASN_OBJECT_ID_E 証明書エンコーディングに無効なオブジェクトIDがある場合に返されます
    \return ECC_CURVE_OID_E 提供されたキーのECC曲線がサポートされていない場合に返されます
    \return ECC_BAD_ARG_E ECCキー形式にエラーがある場合に返されます
    \return NOT_COMPILED_IN 秘密鍵が圧縮されており、圧縮キーが提供されていない場合に返されます
    \return MP_MEM 秘密鍵の解析中に使用される数学ライブラリにエラーがある場合に返されます
    \return MP_VAL 秘密鍵の解析中に使用される数学ライブラリにエラーがある場合に返されます
    \return MP_RANGE 秘密鍵の解析中に使用される数学ライブラリにエラーがある場合に返されます

    \param input 入力秘密鍵を含むバッファへのポインタ
    \param inOutIdx バッファ内で開始するインデックスを含むword32オブジェクトへのポインタ
    \param key デコードされた秘密鍵を格納する初期化されたeccオブジェクトへのポインタ
    \param inSz 秘密鍵を含む入力バッファのサイズ

    _Example_
    \code
    int ret, idx=0;
    ecc_key key; // キーを格納

    byte* tmp; // キーを読み取るための一時バッファ
    tmp = (byte*) malloc(FOURK_BUF);

    int inSz;
    inSz = fread(tmp, 1, FOURK_BUF, privateKeyFile);
    // tmpバッファにキーを読み取る

    wc_ecc_init(&key); // キーを初期化
    ret = wc_EccPrivateKeyDecode(tmp, &idx, &key, (word32)inSz);
    if(ret < 0) {
        // eccキーのデコードエラー
    }
    \endcode

    \sa wc_RSA_PrivateKeyDecode
*/
int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx,
                                           ecc_key* key, word32 inSz);

/*!
    \ingroup ASN

    \brief この関数は、秘密ECCキーをder形式に書き込みます。

    \return Success ECCキーのder形式への書き込みに成功すると、バッファに書き込まれた長さを返します
    \return BAD_FUNC_ARG keyまたはoutputがnull、またはinLenがゼロの場合に返されます
    \return MEMORY_E XMALLOCでメモリを割り当てる際にエラーがある場合に返されます
    \return BUFFER_E 変換された証明書が出力バッファに格納するには大きすぎる場合に返されます
    \return ASN_UNKNOWN_OID_E 使用されているECCキーが不明なタイプの場合に返されます
    \return MP_MEM 秘密鍵の解析中に使用される数学ライブラリにエラーがある場合に返されます
    \return MP_VAL 秘密鍵の解析中に使用される数学ライブラリにエラーがある場合に返されます
    \return MP_RANGE 秘密鍵の解析中に使用される数学ライブラリにエラーがある場合に返されます

    \param key 入力eccキーを含むバッファへのポインタ
    \param output der形式のキーを格納するバッファへのポインタ
    \param inLen der形式のキーを格納するバッファの長さ

    _Example_
    \code
    int derSz;
    ecc_key key;
    // キーを初期化して作成
    byte der[FOURK_BUF];
    // ここにder形式のキーを格納

    derSz = wc_EccKeyToDer(&key, der, FOURK_BUF);
    if(derSz < 0) {
        // eccキーをderバッファに変換する際のエラー
    }
    \endcode

    \sa wc_RsaKeyToDer
*/
int wc_EccKeyToDer(ecc_key* key, byte* output, word32 inLen);

/*!
    \ingroup ASN

    \brief 入力バッファからECC公開鍵をデコードします。ECCキーを取得するためにASNシーケンスを解析します。

    \return 0 成功
    \return BAD_FUNC_ARG いずれかの引数がnullの場合に返されます。
    \return ASN_PARSE_E 解析エラーがある場合に返されます
    \return ASN_ECC_KEY_E キーのインポートエラーがある場合に返されます。
    考えられる理由についてはwc_ecc_import_x963を参照してください。

    \param input デコードするDERエンコードされたキーを含むバッファ。
    \param inOutIdx 入力バッファの読み取り開始位置のインデックス。出力時、インデックスは入力バッファの最後に解析された位置に設定されます。
    \param key 公開鍵を格納するecc_key構造体へのポインタ。
    \param inSz 入力バッファのサイズ。

    _Example_
    \code
    int ret;
    word32 idx = 0;
    byte buff[] = { // キーで初期化 };
    ecc_key pubKey;
    wc_ecc_init(&pubKey);
    if ( wc_EccPublicKeyDecode(buff, &idx, &pubKey, sizeof(buff)) != 0) {
            // キーのデコードエラー
    }
    \endcode

    \sa wc_ecc_import_x963
*/
int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
                          ecc_key* key, word32 inSz);

/*!
    \ingroup ASN

    \brief この関数は、ECC公開鍵をDER形式に変換します。使用されたバッファのサイズを返します。DER形式のECC公開鍵は出力バッファに格納されます。with_AlgCurveフラグは、アルゴリズムと曲線情報を持つヘッダーを含めます

    \return >0 成功、使用されたバッファのサイズ
    \return BAD_FUNC_ARG outputまたはkeyがnullの場合に返されます。
    \return LENGTH_ONLY_E ECC公開鍵のサイズ取得エラー。
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます。

    \param key ECCキーへのポインタ
    \param output 書き込み先の出力バッファへのポインタ。
    \param inLen バッファのサイズ。
    \param with_AlgCurve アルゴリズムと曲線情報を持つヘッダーを含めるタイミングのフラグ。

    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    int derSz = // der用の適切なサイズ;
    byte der[derSz];

    if(wc_EccPublicKeyToDer(&key, der, derSz, 1) < 0)
    {
        // ECC公開鍵のder変換エラー
    }
    \endcode

    \sa wc_EccKeyToDer
    \sa wc_EccPrivateKeyDecode
*/
int wc_EccPublicKeyToDer(ecc_key* key, byte* output,
                                         word32 inLen, int with_AlgCurve);

/*!
    \ingroup ASN

    \brief この関数は、ECC公開鍵をDER形式に変換します。使用されたバッファのサイズを返します。DER形式のECC公開鍵は出力バッファに格納されます。with_AlgCurveフラグは、アルゴリズムと曲線情報を持つヘッダーを含めます。compパラメータは、公開鍵を圧縮形式でエクスポートするかどうかを決定します。

    \return >0 成功、使用されたバッファのサイズ
    \return BAD_FUNC_ARG outputまたはkeyがnullの場合に返されます。
    \return LENGTH_ONLY_E ECC公開鍵のサイズ取得エラー。
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます。

    \param key ECCキーへのポインタ
    \param output 書き込み先の出力バッファへのポインタ。
    \param inLen バッファのサイズ。
    \param with_AlgCurve アルゴリズムと曲線情報を持つヘッダーを含めるタイミングのフラグ。
    \param comp 1（ゼロ以外）の場合、ECC公開鍵は圧縮形式で書き込まれます。0の場合、非圧縮形式で書き込まれます。

    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    int derSz = // der用の適切なサイズ;
    byte der[derSz];

    // 圧縮されたECCキーを書き出す
    if(wc_EccPublicKeyToDer_ex(&key, der, derSz, 1, 1) < 0)
    {
        // ECC公開鍵のder変換エラー
    }
    \endcode

    \sa wc_EccKeyToDer
    \sa wc_EccPublicKeyDecode
*/
int wc_EccPublicKeyToDer_ex(ecc_key* key, byte* output,
                                     word32 inLen, int with_AlgCurve, int comp);


/*!
    \ingroup ASN

    \brief この関数は、DERエンコードされたバッファからCurve25519秘密鍵（のみ）をデコードします

    \return 0 成功
    \return BAD_FUNC_ARG input、inOutIdxまたはkeyがnullの場合に返されます
    \return ASN_PARSE_E DERエンコードされたデータの解析エラーがある場合に返されます
    \return ECC_BAD_ARG_E キー長がCURVE25519_KEYSIZEでない場合、またはDERキーが適切にフォーマットされているにもかかわらず他の問題を含む場合に返されます。
    \return BUFFER_E 入力バッファが有効なDERエンコードされたキーを含むには小さすぎる場合に返されます。

    \param input DERエンコードされた秘密鍵を含むバッファへのポインタ
    \param inOutIdx 入力バッファの読み取り開始位置のインデックス。出力時、インデックスは入力バッファの最後に解析された位置に設定されます。
    \param key デコードされたキーを格納するcurve25519_key構造体へのポインタ
    \param inSz 入力DERバッファのサイズ

    \sa wc_Curve25519KeyDecode
    \sa wc_Curve25519PublicKeyDecode

    _Example_
    \code
    byte der[] = { // DERエンコードされたキー };
    word32 idx = 0;
    curve25519_key key;
    wc_curve25519_init(&key);

    if (wc_Curve25519PrivateKeyDecode(der, &idx, &key, sizeof(der)) != 0) {
        // 秘密鍵のデコードエラー
    }
    \endcode
*/
int wc_Curve25519PrivateKeyDecode(const byte* input, word32* inOutIdx,
                                  curve25519_key* key, word32 inSz);

/*!
    \ingroup ASN

    \brief この関数は、DERエンコードされたバッファからCurve25519公開鍵（のみ）をデコードします。

    \return 0 成功
    \return BAD_FUNC_ARG input、inOutIdxまたはkeyがnullの場合に返されます
    \return ASN_PARSE_E DERエンコードされたデータの解析エラーがある場合に返されます
    \return ECC_BAD_ARG_E キー長がCURVE25519_KEYSIZEでない場合、またはDERキーが適切にフォーマットされているにもかかわらず他の問題を含む場合に返されます。
    \return BUFFER_E 入力バッファが有効なDERエンコードされたキーを含むには小さすぎる場合に返されます。

    \param input DERエンコードされた公開鍵を含むバッファへのポインタ
    \param inOutIdx 入力バッファの読み取り開始位置のインデックス。出力時、インデックスは入力バッファの最後に解析された位置に設定されます。
    \param key デコードされたキーを格納するcurve25519_key構造体へのポインタ
    \param inSz 入力DERバッファのサイズ

    \sa wc_Curve25519KeyDecode
    \sa wc_Curve25519PrivateKeyDecode

    _Example_
    \code
    byte der[] = { // DERエンコードされたキー };
    word32 idx = 0;
    curve25519_key key;
    wc_curve25519_init(&key);
    if (wc_Curve25519PublicKeyDecode(der, &idx, &key, sizeof(der)) != 0) {
        // 公開鍵のデコードエラー
    }
    \endcode
*/
int wc_Curve25519PublicKeyDecode(const byte* input, word32* inOutIdx,
                                 curve25519_key* key, word32 inSz);

/*!
    \ingroup ASN

    \brief この関数は、DERエンコードされたバッファからCurve25519キーをデコードします。秘密鍵、公開鍵、または両方をデコードできます。

    \return 0 成功
    \return BAD_FUNC_ARG input、inOutIdxまたはkeyがnullの場合に返されます
    \return ASN_PARSE_E DERエンコードされたデータの解析エラーがある場合に返されます
    \return ECC_BAD_ARG_E キー長がCURVE25519_KEYSIZEでない場合、またはDERキーが適切にフォーマットされているにもかかわらず他の問題を含む場合に返されます。
    \return BUFFER_E 入力バッファが有効なDERエンコードされたキーを含むには小さすぎる場合に返されます。

    \param input DERエンコードされたキーを含むバッファへのポインタ
    \param inOutIdx 入力バッファの読み取り開始位置のインデックス。出力時、インデックスは入力バッファの最後に解析された位置に設定されます。
    \param key デコードされたキーを格納するcurve25519_key構造体へのポインタ
    \param inSz 入力DERバッファのサイズ

    \sa wc_Curve25519PrivateKeyDecode
    \sa wc_Curve25519PublicKeyDecode

    _Example_
    \code
    byte der[] = { // DERエンコードされたキー };
    word32 idx = 0;
    curve25519_key key;
    wc_curve25519_init(&key);
    if (wc_Curve25519KeyDecode(der, &idx, &key, sizeof(der)) != 0) {
        // キーのデコードエラー
    }
    \endcode
*/
int wc_Curve25519KeyDecode(const byte* input, word32* inOutIdx,
                           curve25519_key* key, word32 inSz);

/*!
    \ingroup ASN

    \brief この関数は、Curve25519秘密鍵をDER形式にエンコードします。入力キー構造体に公開鍵が含まれている場合、それは無視されます。

    \return >0 成功、DERエンコーディングの長さ
    \return BAD_FUNC_ARG keyまたはoutputがnullの場合に返されます
    \return MEMORY_E 割り当て失敗がある場合に返されます
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます

    \param key エンコードする秘密鍵を含むcurve25519_key構造体へのポインタ
    \param output DERエンコーディングを保持するバッファ
    \param inLen 出力バッファのサイズ

    \sa wc_Curve25519KeyToDer
    \sa wc_Curve25519PublicKeyToDer

    _Example_
    \code
    curve25519_key key;
    wc_curve25519_init(&key);
    ...
    int derSz = 128; // 出力DER用の適切なサイズ
    byte der[derSz];
    wc_Curve25519PrivateKeyToDer(&key, der, derSz);
    \endcode
*/
int wc_Curve25519PrivateKeyToDer(curve25519_key* key, byte* output,
                                 word32 inLen);

/*!
    \ingroup ASN

    \brief この関数は、Curve25519公開鍵をDER形式にエンコードします。入力キー構造体に秘密鍵が含まれている場合、それは無視されます。

    \return >0 成功、DERエンコーディングの長さ
    \return BAD_FUNC_ARG keyまたはoutputがnullの場合に返されます
    \return MEMORY_E 割り当て失敗がある場合に返されます
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます

    \param key エンコードする公開鍵を含むcurve25519_key構造体へのポインタ
    \param output DERエンコーディングを保持するバッファ
    \param inLen 出力バッファのサイズ
    \param withAlg DERエンコーディングにアルゴリズム識別子を含めるかどうか

    \sa wc_Curve25519KeyToDer
    \sa wc_Curve25519PrivateKeyToDer

    _Example_
    \code
    curve25519_key key;
    wc_curve25519_init(&key);
    ...
    int derSz = 128; // 出力DER用の適切なサイズ
    byte der[derSz];
    wc_Curve25519PublicKeyToDer(&key, der, derSz, 1);
    \endcode
*/
int wc_Curve25519PublicKeyToDer(curve25519_key* key, byte* output, word32 inLen,
                                int withAlg);

/*!
    \ingroup ASN

    \brief この関数は、Curve25519キーをDER形式にエンコードします。秘密鍵、公開鍵、または両方をエンコードできます。

    \return >0 成功、DERエンコーディングの長さ
    \return BAD_FUNC_ARG keyまたはoutputがnullの場合に返されます
    \return MEMORY_E 割り当て失敗がある場合に返されます
    \return BUFFER_E 出力バッファが小さすぎる場合に返されます

    \param key エンコードするキーを含むcurve25519_key構造体へのポインタ
    \param output DERエンコーディングを保持するバッファ
    \param inLen 出力バッファのサイズ
    \param withAlg DERエンコーディングにアルゴリズム識別子を含めるかどうか

    \sa wc_Curve25519PrivateKeyToDer
    \sa wc_Curve25519PublicKeyToDer

    _Example_
    \code
    curve25519_key key;
    wc_curve25519_init(&key);
    ...
    int derSz = 128; // 出力DER用の適切なサイズ
    byte der[derSz];
    wc_Curve25519KeyToDer(&key, der, derSz, 1);
    \endcode
*/
int wc_Curve25519KeyToDer(curve25519_key* key, byte* output, word32 inLen,
                          int withAlg);

/*!
    \ingroup ASN

    \brief この関数は、デジタル署名を出力バッファにエンコードし、作成されたエンコードされた署名のサイズを返します。

    \return Success エンコードされた署名をoutputに正常に書き込むと、バッファに書き込まれた長さを返します

    \param out エンコードされた署名が書き込まれるバッファへのポインタ
    \param digest 署名のエンコードに使用するダイジェストへのポインタ
    \param digSz ダイジェストを含むバッファの長さ
    \param hashOID 署名の生成に使用されるハッシュタイプを識別するOID。ビルド構成に応じた有効なオプションは：SHAh、SHA256h、SHA384h、SHA512h、MD2h、MD5h、DESb、DES3b、CTC_MD5wRSA、CTC_SHAwRSA、CTC_SHA256wRSA、CTC_SHA384wRSA、CTC_SHA512wRSA、CTC_SHAwECDSA、CTC_SHA256wECDSA、CTC_SHA384wECDSA、およびCTC_SHA512wECDSA。

    \endcode
    \code
    int signSz;
    byte encodedSig[MAX_ENCODED_SIG_SZ];
    Sha256 sha256;
    // ハッシュ化のためにsha256を初期化

    byte* dig = = (byte*)malloc(WC_SHA256_DIGEST_SIZE);
    // ハッシュ化とハッシュ更新を実行してdigにSHA-256ハッシュを格納
    // （wc_InitSha256、wc_Sha256Update、wc_Sha256Finalを参照）
    signSz = wc_EncodeSignature(encodedSig, dig, WC_SHA256_DIGEST_SIZE, SHA256h);
    \endcode

    \sa なし
*/
word32 wc_EncodeSignature(byte* out, const byte* digest,
                                      word32 digSz, int hashOID);

/*!
    \ingroup ASN

    \brief この関数は、ハッシュタイプに対応するハッシュOIDを返します。例えば、WC_SHA512タイプが与えられた場合、この関数はSHA512ハッシュに対応する識別子SHA512hを返します。

    \return Success 成功時に、その暗号化タイプで使用する適切なハッシュに対応するOIDを返します。
    \return 0 認識されないハッシュタイプが引数として渡された場合に返されます。

    \param type OIDを見つけるハッシュタイプ。ビルド構成に応じた有効なオプションには：WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512

    _Example_
    \code
    int hashOID;

    hashOID = wc_GetCTC_HashOID(WC_SHA512);
    if (hashOID == 0) {
	    // WOLFSSL_SHA512が定義されていません
    }
    \endcode

    \sa なし
*/
int wc_GetCTC_HashOID(int type);

/*!
    \ingroup ASN

    \brief この関数は、証明書構造体のデコードされた証明書キャッシュによって使用されるメモリとリソースをクリーンアップします。WOLFSSL_CERT_GEN_CACHEが定義されている場合、デコードされた証明書構造体は証明書構造体にキャッシュされます。これにより、証明書設定関数への後続の呼び出しで、各呼び出しでデコードされた証明書を解析することを回避できます。

    \return 0 成功時。
    \return BAD_FUNC_ARG 無効なポインタが引数として渡された場合に返されます。

    \param cert 初期化されていない証明書情報構造体へのポインタ。

    _Example_
    \code
    Cert cert; // 初期化された証明書構造体

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

    \brief この関数は、PKCS#8暗号化されていないバッファ内の従来の秘密鍵の先頭を見つけます。

    \return Length 成功時に従来の秘密鍵の長さ。
    \return Negative 失敗時に負の値。

    \param input 暗号化されていないPKCS#8秘密鍵を含むバッファ。
    \param inOutIdx 入力バッファへのインデックス。入力時、PKCS#8バッファの先頭へのバイトオフセットである必要があります。出力時、入力バッファ内の従来の秘密鍵へのバイトオフセットになります。
    \param sz 入力バッファのバイト数。

    _Example_
    \code
    byte* pkcs8Buf; // PKCS#8キーを含むバッファ。
    word32 idx = 0;
    word32 sz; // pkcs8Bufのサイズ。
    ...
    ret = wc_GetPkcs8TraditionalOffset(pkcs8Buf, &idx, sz);
    // pkcs8Buf + idxは従来の秘密鍵バイトの先頭になります。
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

    \brief この関数は、DER秘密鍵を受け取り、PKCS#8形式に変換します。PKCS#12縮小キーバッグの作成にも使用されます。RFC 5208を参照してください。

    \return The 成功時にoutに配置されたPKCS#8キーのサイズ。
    \return LENGTH_ONLY_E outがNULLの場合、outSzに必要な出力バッファサイズが返されます。
    \return Other 失敗時に負の値。

    \param out 結果を配置するバッファ。NULLの場合、outSzに必要な出力バッファサイズが返されます。
    \param outSz outバッファのサイズ。
    \param key 従来のDERキーを持つバッファ。
    \param keySz keyバッファのサイズ。
    \param algoID アルゴリズムID（例：RSAk）。
    \param curveOID 使用される場合のECC曲線OID。RSAキーの場合はNULLである必要があります。
    \param oidSz 曲線OIDのサイズ。curveOIDがNULLの場合は0に設定されます。

    _Example_
    \code
    ecc_key eccKey;              // wolfSSL ECCキーオブジェクト。
    byte* der;                   // DERエンコードされたECCキー。
    word32 derSize;              // derのサイズ。
    const byte* curveOid = NULL; // eccKeyで使用される曲線のOID。
    word32 curveOidSz = 0;       // 曲線OIDのサイズ。
    byte* pkcs8;                 // PKCS#8キー用の出力バッファ。
    word32 pkcs8Sz;              // 出力バッファのサイズ。

    derSize = wc_EccKeyDerSize(&eccKey, 1);
    ...
    derSize = wc_EccKeyToDer(&eccKey, der, derSize);
    ...
    ret = wc_ecc_get_oid(eccKey.dp->oidSum, &curveOid, &curveOidSz);
    ...
    ret = wc_CreatePKCS8Key(NULL, &pkcs8Sz, der,
        derSize, ECDSAk, curveOid, curveOidSz); // pkcs8Szに必要なサイズを取得。
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

    \brief この関数は、暗号化されていないPKCS#8 DERキー（例：wc_CreatePKCS8Keyによって作成されたもの）を受け取り、PKCS#8暗号化形式に変換します。結果の暗号化されたキーは、wc_DecryptPKCS8Keyを使用して復号できます。RFC 5208を参照してください。

    \return The 成功時にoutに配置された暗号化されたキーのサイズ。
    \return LENGTH_ONLY_E outがNULLの場合、outSzに必要な出力バッファサイズが返されます。
    \return Other 失敗時に負の値。

    \param key 従来のDERキーを持つバッファ。
    \param keySz keyバッファのサイズ。
    \param out 結果を配置するバッファ。NULLの場合、outSzに必要な出力バッファサイズが返されます。
    \param outSz outバッファのサイズ。
    \param password パスワードベースの暗号化アルゴリズムに使用するパスワード。
    \param passwordSz パスワードの長さ（NULLターミネータを含まない）。
    \param vPKCS 使用するPKCSバージョン。PKCS12またはPKCS5の場合は1。
    \param pbeOid 使用するPBEスキームのOID（例：PBES2またはRFC 2898 A.3のPBES1のOIDの1つ）。
    \param encAlgId 使用する暗号化アルゴリズムID（例：AES256CBCb）。
    \param salt 使用するソルトバッファ。NULLの場合、ランダムなソルトが使用されます。
    \param saltSz ソルトバッファの長さ。saltにNULLを渡す場合は0。
    \param itt KDFに使用する反復回数。
    \param rng 初期化されたWC_RNGオブジェクトへのポインタ。
    \param heap 動的割り当てに使用されるヒープへのポインタ。NULLでも可。

    _Example_
    \code
    byte* pkcs8;          // 暗号化されていないPKCS#8キー。
    word32 pkcs8Sz;       // pkcs8のサイズ。
    byte* pkcs8Enc;       // 暗号化されたPKCS#8キー。
    word32 pkcs8EncSz;    // pkcs8Encのサイズ。
    const char* password; // 暗号化に使用するパスワード。
    int passwordSz;       // パスワードの長さ（NULLターミネータを含まない）。
    WC_RNG rng;

    // 以下は、pkcs8Encにpkcs8の暗号化されたバージョンを生成します。暗号化は
    // PKCS#5のパスワードベース暗号化スキーム2（PBE2）とCBCモードの256ビット
    // キーを持つAES暗号を使用します。PKCS#5の詳細についてはRFC 8018を参照してください。
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

    \brief この関数は、暗号化されたPKCS#8 DERキーを受け取り、PKCS#8暗号化されていないDERに復号します。wc_EncryptPKCS8Keyによって行われた暗号化を元に戻します。RFC5208を参照してください。入力バッファは復号されたデータで上書きされます。

    \return The 成功時に復号されたバッファの長さ。
    \return Negative 失敗時に負の値。

    \param input 入力時、暗号化されたPKCS#8キーを含むバッファ。出力が成功すると、復号されたキーを含みます。
    \param sz 入力バッファのサイズ。
    \param password キーの暗号化に使用されたパスワード。
    \param passwordSz パスワードの長さ（NULLターミネータを含まない）。

    _Example_
    \code
    byte* pkcs8Enc;       // wc_EncryptPKCS8Keyで作成された暗号化されたPKCS#8キー。
    word32 pkcs8EncSz;    // pkcs8Encのサイズ。
    const char* password; // 復号に使用するパスワード。
    int passwordSz;       // パスワードの長さ（NULLターミネータを含まない）。

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

    \brief この関数は、従来のDERキーを受け取り、PKCS#8形式に変換し、暗号化します。これを行うためにwc_CreatePKCS8Keyとwc_EncryptPKCS8Keyを使用します。

    \return The 成功時にoutに配置された暗号化されたキーのサイズ。
    \return LENGTH_ONLY_E outがNULLの場合、outSzに必要な出力バッファサイズが返されます。
    \return Other 失敗時に負の値。

    \param key 従来のDERキーを持つバッファ。
    \param keySz keyバッファのサイズ。
    \param out 結果を配置するバッファ。NULLの場合、outSzに必要な出力バッファサイズが返されます。
    \param outSz outバッファのサイズ。
    \param password パスワードベースの暗号化アルゴリズムに使用するパスワード。
    \param passwordSz パスワードの長さ（NULLターミネータを含まない）。
    \param vPKCS 使用するPKCSバージョン。PKCS12またはPKCS5の場合は1。
    \param pbeOid 使用するPBEスキームのOID（例：PBES2またはRFC 2898 A.3のPBES1のOIDの1つ）。
    \param encAlgId 使用する暗号化アルゴリズムID（例：AES256CBCb）。
    \param salt 使用するソルトバッファ。NULLの場合、ランダムなソルトが使用されます。
    \param saltSz ソルトバッファの長さ。saltにNULLを渡す場合は0。
    \param itt KDFに使用する反復回数。
    \param rng 初期化されたWC_RNGオブジェクトへのポインタ。
    \param heap 動的割り当てに使用されるヒープへのポインタ。NULLでも可。

    _Example_
    \code
    byte* key;            // 従来の秘密鍵（DER形式）。
    word32 keySz;         // keyのサイズ。
    byte* pkcs8Enc;       // 暗号化されたPKCS#8キー。
    word32 pkcs8EncSz;    // pkcs8Encのサイズ。
    const char* password; // 暗号化に使用するパスワード。
    int passwordSz;       // パスワードの長さ（NULLターミネータを含まない）。
    WC_RNG rng;

    // 以下は、pkcs8Encにkeyの暗号化されたPKCS#8バージョンを生成します。
    // 暗号化はPKCS#5のパスワードベース暗号化スキーム2（PBE2）とCBCモードの
    // 256ビットキーを持つAES暗号を使用します。PKCS#5の詳細については
    // RFC 8018を参照してください。
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

    \brief この関数は、"cert"パラメータが指すDecodedCertを初期化します。長さ"inSz"のDERエンコードされた証明書への"source"ポインタを保存します。この証明書は、wc_ParseCertへの後続の呼び出しによって解析できます。

    \param cert 割り当てられたDecodedCertオブジェクトへのポインタ。
    \param source DERエンコードされた証明書へのポインタ。
    \param inSz DERエンコードされた証明書の長さ（バイト単位）。
    \param heap 動的割り当てに使用されるヒープへのポインタ。NULLでも可。

    _Example_
    \code
    DecodedCert decodedCert; // デコードされた証明書オブジェクト。
    byte* certBuf;           // DERエンコードされた証明書バッファ。
    word32 certBufSz;        // certBufのサイズ（バイト単位）。

    wc_InitDecodedCert(&decodedCert, certBuf, certBufSz, NULL);
    \endcode

    \sa wc_ParseCert
    \sa wc_FreeDecodedCert
*/
void wc_InitDecodedCert(struct DecodedCert* cert,
    const byte* source, word32 inSz, void* heap);

/*!
    \ingroup ASN

    \brief この関数は、DecodedCertオブジェクトに保存されたDERエンコードされた証明書を解析し、そのオブジェクトのフィールドを設定します。DecodedCertは、wc_InitDecodedCertへの事前の呼び出しで初期化されている必要があります。この関数は、CertificateManagerオブジェクトへのオプションのポインタを取り、CAがCertificateManagerで見つかった場合、DecodedCertの証明機関情報を設定するために使用されます。

    \return 0 成功時。
    \return Other 失敗時に負の値。

    \param cert 初期化されたDecodedCertオブジェクトへのポインタ。
    \param type 証明書のタイプ。asn_public.hのCertType列挙型を参照してください。
    \param verify 設定されている場合、ユーザーが証明書の有効性を検証したいことを示すフラグ。
    \param cm CertificateManagerへのオプションのポインタ。NULLでも可。

    _Example_
    \code
    int ret;
    DecodedCert decodedCert; // デコードされた証明書オブジェクト。
    byte* certBuf;           // DERエンコードされた証明書バッファ。
    word32 certBufSz;        // certBufのサイズ（バイト単位）。

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

    \brief この関数は、wc_InitDecodedCertで以前に初期化されたDecodedCertを解放します。

    \param cert 初期化されたDecodedCertオブジェクトへのポインタ。

    _Example_
    \code
    int ret;
    DecodedCert decodedCert; // デコードされた証明書オブジェクト。
    byte* certBuf;           // DERエンコードされた証明書バッファ。
    word32 certBufSz;        // certBufのサイズ（バイト単位）。

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

    \brief この関数は、wolfSSLが現在時刻を取得する必要があるときに使用される時刻コールバックを登録します。コールバックのプロトタイプは、C標準ライブラリの"time"関数と同じである必要があります。

    \return 0 成功時に返されます。

    \param f 時刻コールバックとして登録する関数。

    _Example_
    \code
    int ret = 0;
    // 時刻コールバックのプロトタイプ
    time_t my_time_cb(time_t* t);
    // 登録する
    ret = wc_SetTimeCb(my_time_cb);
    if (ret != 0) {
        // 時刻コールバックの設定失敗
    }
    time_t my_time_cb(time_t* t)
    {
        // カスタム時刻関数
    }
    \endcode

    \sa wc_Time
*/
int wc_SetTimeCb(wc_time_cb f);

/*!
    \ingroup ASN

    \brief この関数は、現在時刻を取得します。デフォルトでは、プラットフォーム間で異なるXTIMEマクロを使用します。ユーザーは、wc_SetTimeCb関数を介して任意の関数を使用できます。

    \return Time 成功時に返される現在時刻。

    \param t 現在時刻を設定するオプションのtime_tポインタ。

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

    \brief この関数は、X.509証明書にカスタム拡張を挿入します。
     注：ポインタであるパラメータのいずれかが指すアドレスのコンテンツは、
           証明書が生成されてder出力が得られるまで変更してはいけません。
           この関数はコンテンツを別のバッファにコピーしません。

    \return 0 成功時に返されます。
    \return Other 失敗時に負の値。

    \param cert 初期化されたDecodedCertオブジェクトへのポインタ。
    \param critical 0の場合、拡張は重要としてマークされません。それ以外の場合は重要としてマークされます。
    \param oid ドット区切りのoidを文字列として。例："1.2.840.10045.3.1.7"
    \param der 拡張のコンテンツのderエンコーディング。
    \param derSz derエンコーディングのサイズ（バイト単位）。


    _Example_
    \code
    int ret = 0;
    Cert newCert;
    wc_InitCert(&newCert);

    // subject、公開鍵、発行者、その他のものを設定するコードがここに入ります。

    ret = wc_SetCustomExtension(&newCert, 1, "1.2.3.4.5",
              (const byte *)"This is a critical extension", 28);
    if (ret < 0) {
        // 拡張の設定失敗。
    }

    ret = wc_SetCustomExtension(&newCert, 0, "1.2.3.4.6",
              (const byte *)"This is NOT a critical extension", 32)
    if (ret < 0) {
        // 拡張の設定失敗。
    }

    // 証明書に署名してから書き出すコードがここに入ります。

    \endcode

    \sa wc_InitCert
    \sa wc_SetUnknownExtCallback
*/
int wc_SetCustomExtension(Cert *cert, int critical, const char *oid,
                                      const byte *der, word32 derSz);

/*!
    \ingroup ASN

    \brief この関数は、wolfSSLが証明書の解析中に証明書内の不明なX.509拡張に遭遇したときに使用されるコールバックを登録します。コールバックのプロトタイプは次のようにする必要があります：

    \return 0 成功時に返されます。
    \return Other 失敗時に負の値。

    \param cert このコールバックに関連付けられるDecodedCert構造体。
    \param cb 時刻コールバックとして登録する関数。

    _Example_
    \code
    int ret = 0;
    // 不明な拡張コールバックのプロトタイプ
    int myUnknownExtCallback(const word16* oid, word32 oidSz, int crit,
                             const unsigned char* der, word32 derSz);

    // 登録する
    ret = wc_SetUnknownExtCallback(cert, myUnknownExtCallback);
    if (ret != 0) {
        // コールバックの設定失敗
    }

    // oid: oidのドット区切り値である整数の配列。
    // oidSz: oid内の値の数。
    // crit: 拡張が重要としてマークされたかどうか。
    // der: 拡張のコンテンツのderエンコーディング。
    // derSz: derエンコーディングのサイズ（バイト単位）。
    int myCustomExtCallback(const word16* oid, word32 oidSz, int crit,
                            const unsigned char* der, word32 derSz) {

        // 拡張を解析するロジックがここに入ります。

        // 注：0を返すことで、この拡張を受け入れ、wolfSSLに
        // それが許容可能であることを通知しています。許容できない拡張が
        // 見つかった場合は、エラーを返す必要があります。重要フラグが
        // 設定された不明な拡張に遭遇した場合の標準的な動作は、
        // ASN_CRIT_EXT_Eを返すことです。簡潔にするため、この例では
        // 常にすべての拡張を受け入れています。異なるロジックを
        // 使用する必要があります。
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

    \brief この関数は、X.509証明書のder形式の署名を公開鍵に対して検証します。公開鍵は、der形式の完全なサブジェクト公開鍵情報であることが期待されます。

    \return 0 成功時に返されます。
    \return Other 失敗時に負の値。

    \param cert X.509証明書のderエンコーディング。
    \param certSz certのサイズ（バイト単位）。
    \param heap 動的割り当てに使用されるヒープへのポインタ。NULLでも可。
    \param pubKey 公開鍵のderエンコーディング。
    \param pubKeySz pubKeyのサイズ（バイト単位）。
    \param pubKeyOID 公開鍵のアルゴリズムを識別するOID。
    (例：ECDSAk、DSAkまたはRSAk)
*/
int wc_CheckCertSigPubKey(const byte* cert, word32 certSz,
                                      void* heap, const byte* pubKey,
                                      word32 pubKeySz, int pubKeyOID);

/*!
    \ingroup ASN

    \brief この関数は、ASN.1プリントオプションを初期化します。

    \return  0 成功時。
    \return  BAD_FUNC_ARG asn1がNULLの場合。

    \param opts  プリント用のASN.1オプション。

    _Example_
    \code
    Asn1PrintOptions opt;

    // 使用前にASN.1プリントオプションを初期化します。
    wc_Asn1PrintOptions_Init(&opt);
    \endcode
    \sa wc_Asn1PrintOptions_Set
    \sa wc_Asn1_PrintAll
*/
int wc_Asn1PrintOptions_Init(Asn1PrintOptions* opts);

/*!
    \ingroup ASN

    \brief この関数は、ASN.1プリントオプションオブジェクトにプリントオプションを設定します。

    \return  0 成功時。
    \return  BAD_FUNC_ARG asn1がNULLの場合。
    \return  BAD_FUNC_ARG valがoptionの範囲外の場合。

    \param opts  プリント用のASN.1オプション。
    \param opt   値を設定するオプション。
    \param val   設定する値。

    _Example_
    \code
    Asn1PrintOptions opt;

    // 使用前にASN.1プリントオプションを初期化します。
    wc_Asn1PrintOptions_Init(&opt);
    // タグ名をプリントする際のインデント数を1に設定します。
    wc_Asn1PrintOptions_Set(&opt, ASN1_PRINT_OPT_INDENT, 1);
    \endcode

    \sa wc_Asn1PrintOptions_Init
    \sa wc_Asn1_PrintAll
*/
int wc_Asn1PrintOptions_Set(Asn1PrintOptions* opts, enum Asn1PrintOpt opt,
    word32 val);

/*!
    \ingroup ASN

    \brief この関数は、ASN.1解析オブジェクトを初期化します。

    \return  0 成功時。
    \return  BAD_FUNC_ARG asn1がNULLの場合。

    \param asn1  ASN.1解析オブジェクト。

    _Example_
    \code
    Asn1 asn1;

    // 使用前にASN.1解析オブジェクトを初期化します。
    wc_Asn1_Init(&asn1);
    \endcode

    \sa wc_Asn1_SetFile
    \sa wc_Asn1_PrintAll
 */
int wc_Asn1_Init(Asn1* asn1);

/*!
    \ingroup ASN

    \brief この関数は、ASN.1解析オブジェクトへのプリント時に使用するファイルを設定します。

    \return  0 成功時。
    \return  BAD_FUNC_ARG asn1がNULLの場合。
    \return  BAD_FUNC_ARG fileがXBADFILEの場合。

    \param asn1  ASN.1解析オブジェクト。
    \param file  プリント先のファイル。

    _Example_
    \code
    Asn1 asn1;

    // 使用前にASN.1解析オブジェクトを初期化します。
    wc_Asn1_Init(&asn1);
    // 標準出力を書き込み先のファイル記述子として設定します。
    wc_Asn1_SetFile(&asn1, stdout);
    \endcode

    \sa wc_Asn1_Init
    \sa wc_Asn1_PrintAll
 */
int wc_Asn1_SetFile(Asn1* asn1, XFILE file);

/*!
    \ingroup ASN

    \brief すべてのASN.1項目をプリントします。

    \return  0 成功時。
    \return  BAD_FUNC_ARG asn1またはoptsがNULLの場合。
    \return  ASN_LEN_E ASN.1項目の長さが長すぎる場合。
    \return  ASN_DEPTH_E 終了オフセットが無効な場合。
    \return  ASN_PARSE_E ASN.1項目のすべてが解析されなかった場合。

    \param asn1  ASN.1解析オブジェクト。
    \param opts  ASN.1プリントオプション。
    \param data  プリントするBER/DERデータを含むバッファ。
    \param len   プリントするデータの長さ（バイト単位）。

    \code
    Asn1PrintOptions opts;
    Asn1 asn1;
    unsigned char data[] = { DER/BERデータで初期化 };
    word32 len = sizeof(data);

    // 使用前にASN.1プリントオプションを初期化します。
    wc_Asn1PrintOptions_Init(&opt);
    // タグ名をプリントする際のインデント数を1に設定します。
    wc_Asn1PrintOptions_Set(&opt, ASN1_PRINT_OPT_INDENT, 1);

    // 使用前にASN.1解析オブジェクトを初期化します。
    wc_Asn1_Init(&asn1);
    // 標準出力を書き込み先のファイル記述子として設定します。
    wc_Asn1_SetFile(&asn1, stdout);
    // 指定されたプリントオプションでバッファ内のすべてのASN.1項目をプリントします。
    wc_Asn1_PrintAll(&asn1, &opts, data, len);
    \endcode

    \sa wc_Asn1_Init
    \sa wc_Asn1_SetFile
 */
int wc_Asn1_PrintAll(Asn1* asn1, Asn1PrintOptions* opts, unsigned char* data,
    word32 len);