/*!
    \ingroup SHE
    \brief ヒープヒントとデバイスIDを指定してSHEコンテキストを初期化します。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheがNULLの場合に返されます

    \param she 初期化するwc_SHE構造体へのポインタ
    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID、またはソフトウェアのみで処理する場合はINVALID_DEVID

    _Example_
    \code
    wc_SHE she;
    int ret;
    ret = wc_SHE_Init(&she, NULL, INVALID_DEVID);
    if (ret == 0) {
        // sheコンテキストを使用します
    }
    wc_SHE_Free(&she);
    \endcode

    \sa wc_SHE_Init_Id
    \sa wc_SHE_Init_Label
    \sa wc_SHE_Free
*/
int wc_SHE_Init(wc_SHE* she, void* heap, int devId);

/*!
    \ingroup SHE
    \brief 不透明なハードウェア鍵識別子を指定してSHEコンテキストを初期化します。暗号コールバックを使用し、スロットや鍵グループの情報を判別するためにSHEコンテキストへ追加情報を付加する必要がある場合に有用です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheがNULLの場合、lenが0より大きいにもかかわらずidがNULLの場合、またはlenがWC_SHE_MAX_ID_LENを超える場合に返されます

    \param she 初期化するwc_SHE構造体へのポインタ
    \param id 不透明な鍵識別子のバイト列
    \param len idのバイト単位の長さ(0からWC_SHE_MAX_ID_LEN)
    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID

    _Example_
    \code
    wc_SHE she;
    unsigned char myId[] = { 0x01, 0x02, 0x03 };
    int ret;
    ret = wc_SHE_Init_Id(&she, myId, sizeof(myId), NULL, myDevId);
    \endcode

    \sa wc_SHE_Init
    \sa wc_SHE_Init_Label
    \sa wc_SHE_Free
*/
int wc_SHE_Init_Id(wc_SHE* she, unsigned char* id, int len,
                    void* heap, int devId);

/*!
    \ingroup SHE
    \brief 人間が読める鍵ラベルを指定してSHEコンテキストを初期化します。暗号コールバックを使用し、スロットや鍵グループの情報を判別するためにSHEコンテキストへ追加情報を付加する必要がある場合に有用です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheまたはlabelがNULLの場合、あるいはlabelの長さがWC_SHE_MAX_LABEL_LENを超える場合に返されます

    \param she 初期化するwc_SHE構造体へのポインタ
    \param label NUL終端された鍵ラベル文字列
    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID

    _Example_
    \code
    wc_SHE she;
    int ret;
    ret = wc_SHE_Init_Label(&she, "ecu-master-key", NULL, myDevId);
    \endcode

    \sa wc_SHE_Init
    \sa wc_SHE_Init_Id
    \sa wc_SHE_Free
*/
int wc_SHE_Init_Label(wc_SHE* she, const char* label,
                       void* heap, int devId);

/*!
    \ingroup SHE
    \brief すべてのデータを消去し、SHEコンテキストをゼロクリアします。NULLポインタに対して呼び出しても安全です。

    \param she wc_SHE構造体へのポインタ、またはNULL

    _Example_
    \code
    wc_SHE she;
    wc_SHE_Init(&she, NULL, INVALID_DEVID);
    // ... コンテキストを使用 ...
    wc_SHE_Free(&she);
    \endcode

    \sa wc_SHE_Init
*/
void wc_SHE_Free(wc_SHE* she);

/*!
    \ingroup SHE
    \brief 暗号コールバックを介してハードウェアからUIDを取得します。WOLF_CRYPTO_CBが有効で、かつNO_WC_SHE_GETUIDが定義されていないことが必要です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG she、uid、uidSzのいずれかが無効な場合に返されます
    \return CRYPTOCB_UNAVAILABLE コールバックが登録されていない場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param uid 15バイト(120ビット)のSHE UIDを受け取るバッファ
    \param uidSz uidバッファのバイト単位のサイズ(WC_SHE_UID_SZ以上でなければなりません)
    \param ctx コールバックに渡される読み取り専用の呼び出し側コンテキスト(例: チャレンジバッファ、HSMハンドル)

    _Example_
    \code
    byte uid[WC_SHE_UID_SZ];
    int ret;
    ret = wc_SHE_GetUID(&she, uid, sizeof(uid), NULL);
    \endcode

    \sa wc_SHE_GetCounter
*/
int wc_SHE_GetUID(wc_SHE* she, byte* uid, word32 uidSz,
                   const void* ctx);

/*!
    \ingroup SHE
    \brief 暗号コールバックを介してハードウェアから単調増加カウンタの値を取得します。SHE仕様では28ビットのカウンタを使用します。呼び出し側は、この値をGenerateM1M2M3またはGenerateM4M5に渡す前にインクリメントしてください。WOLF_CRYPTO_CBが有効で、かつNO_WC_SHE_GETCOUNTERが定義されていないことが必要です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheまたはcounterがNULLの場合に返されます
    \return CRYPTOCB_UNAVAILABLE コールバックが登録されていない場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param counter 現在のカウンタ値を受け取るポインタ
    \param ctx コールバックに渡される読み取り専用の呼び出し側コンテキスト

    _Example_
    \code
    word32 counter;
    int ret;
    ret = wc_SHE_GetCounter(&she, &counter, NULL);
    \endcode

    \sa wc_SHE_GetUID
*/
int wc_SHE_GetCounter(wc_SHE* she, word32* counter,
                       const void* ctx);

/*!
    \ingroup SHE
    \brief Miyaguchi-Preneel鍵導出で使用するKDF定数をカスタム値に設定します。デフォルト値はSHE仕様のKEY_UPDATE_ENC_CおよびKEY_UPDATE_MAC_Cです。どちらのポインタもNULLにでき、NULLを指定した側の定数は変更されません。WOLFSSL_SHE_EXTENDEDが必要です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheがNULLの場合、または対応するポインタがNULLでないにもかかわらずサイズがWC_SHE_KEY_SZでない場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param encC 16バイトの暗号化導出定数(CENC)、またはNULL
    \param encCSz encCがNULLでない場合はWC_SHE_KEY_SZ(16)でなければなりません
    \param macC 16バイトのMAC導出定数(CMAC)、またはNULL
    \param macCSz macCがNULLでない場合はWC_SHE_KEY_SZ(16)でなければなりません

    _Example_
    \code
    byte myEncC[WC_SHE_KEY_SZ] = { ... };
    byte myMacC[WC_SHE_KEY_SZ] = { ... };
    int ret;
    ret = wc_SHE_SetKdfConstants(&she, myEncC, WC_SHE_KEY_SZ,
                                  myMacC, WC_SHE_KEY_SZ);
    \endcode

    \sa wc_SHE_SetM2Header
    \sa wc_SHE_SetM4Header
    \sa wc_SHE_GenerateM1M2M3
*/
int wc_SHE_SetKdfConstants(wc_SHE* she,
                            const byte* encC, word32 encCSz,
                            const byte* macC, word32 macCSz);

/*!
    \ingroup SHE
    \brief M2の平文ヘッダ(暗号化前のM2の先頭16バイト)を上書きします。設定すると、GenerateM1M2M3はカウンタとフラグから自動生成する代わりにこの値を使用します。WOLFSSL_SHE_EXTENDEDが必要です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheまたはheaderがNULLの場合、あるいはheaderSzがWC_SHE_KEY_SZでない場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param header 16バイトの平文ヘッダブロック
    \param headerSz WC_SHE_KEY_SZ(16)でなければなりません

    _Example_
    \code
    byte header[WC_SHE_KEY_SZ] = { ... };
    int ret;
    ret = wc_SHE_SetM2Header(&she, header, WC_SHE_KEY_SZ);
    \endcode

    \sa wc_SHE_SetKdfConstants
    \sa wc_SHE_SetM4Header
    \sa wc_SHE_GenerateM1M2M3
*/
int wc_SHE_SetM2Header(wc_SHE* she,
                        const byte* header, word32 headerSz);

/*!
    \ingroup SHE
    \brief M4の平文カウンタブロック(K3で暗号化される16バイトのブロック)を上書きします。設定すると、GenerateM4M5はカウンタから自動生成する代わりにこの値を使用します。WOLFSSL_SHE_EXTENDEDが必要です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheまたはheaderがNULLの場合、あるいはheaderSzがWC_SHE_KEY_SZでない場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param header 16バイトの平文カウンタブロック
    \param headerSz WC_SHE_KEY_SZ(16)でなければなりません

    _Example_
    \code
    byte header[WC_SHE_KEY_SZ] = { ... };
    int ret;
    ret = wc_SHE_SetM4Header(&she, header, WC_SHE_KEY_SZ);
    \endcode

    \sa wc_SHE_SetKdfConstants
    \sa wc_SHE_SetM2Header
    \sa wc_SHE_GenerateM4M5
*/
int wc_SHE_SetM4Header(wc_SHE* she,
                        const byte* header, word32 headerSz);

/*!
    \ingroup SHE
    \brief 外部から提供されたM1/M2/M3をSHEコンテキストにインポートします。生成済みフラグが設定されるため、GenerateM4M5のコールバックはコンテキストからM1/M2/M3を読み取ってハードウェアへ送信できます。WOLF_CRYPTO_CBが有効で、かつNO_WC_SHE_IMPORT_M123が定義されていないことが必要です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheがNULLの場合、またはいずれかのメッセージサイズが正しくない場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param m1 16バイトのM1メッセージ(UID | KeyID | AuthID)
    \param m1Sz WC_SHE_M1_SZ(16)でなければなりません
    \param m2 32バイトのM2メッセージ(暗号化されたcounter|flags|pad|newkey)
    \param m2Sz WC_SHE_M2_SZ(32)でなければなりません
    \param m3 16バイトのM3メッセージ(M1|M2に対するCMAC)
    \param m3Sz WC_SHE_M3_SZ(16)でなければなりません

    _Example_
    \code
    int ret;
    ret = wc_SHE_ImportM1M2M3(&she,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ);
    \endcode

    \sa wc_SHE_GenerateM1M2M3
    \sa wc_SHE_GenerateM4M5
    \sa wc_SHE_LoadKey
*/
int wc_SHE_ImportM1M2M3(wc_SHE* she,
                          const byte* m1, word32 m1Sz,
                          const byte* m2, word32 m2Sz,
                          const byte* m3, word32 m3Sz);

/*!
    \ingroup SHE
    \brief SHEの鍵更新メッセージM1、M2、M3を生成し、呼び出し側が用意したバッファへ書き込みます。認可鍵からK1とK2を導出するためにMiyaguchi-Preneel AES-128 KDFを、新しい鍵の暗号化(M2)にAES-CBCを、認証(M3)にAES-CMACを使用します。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、サイズが正しくない場合、またはcounter、flags、authKeyId、targetKeyIdがパックされるフィールドの幅を超える場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param uid 15バイトのSHE UID(120ビットのECU/モジュール識別子)
    \param uidSz WC_SHE_UID_SZ(15)でなければなりません
    \param authKeyId 認可鍵の4ビットのスロットID
    \param authKey 認可鍵の16バイトの値
    \param authKeySz WC_SHE_KEY_SZ(16)でなければなりません
    \param targetKeyId ロード対象の鍵の4ビットのスロットID
    \param newKey ロードする新しい鍵の16バイトの値
    \param newKeySz WC_SHE_KEY_SZ(16)でなければなりません
    \param counter 28ビットの単調増加カウンタ値(対象スロットに格納されているカウンタより大きい値でなければなりません。同じ値は使用できません)
    \param flags 鍵保護フラグ(下位4ビット)
    \param m1 M1の出力バッファ(16バイト)
    \param m1Sz m1バッファのサイズ。WC_SHE_M1_SZ以上でなければなりません
    \param m2 M2の出力バッファ(32バイト)
    \param m2Sz m2バッファのサイズ。WC_SHE_M2_SZ以上でなければなりません
    \param m3 M3の出力バッファ(16バイト)
    \param m3Sz m3バッファのサイズ。WC_SHE_M3_SZ以上でなければなりません

    _Example_
    \code
    byte m1[WC_SHE_M1_SZ], m2[WC_SHE_M2_SZ], m3[WC_SHE_M3_SZ];
    int ret;
    ret = wc_SHE_GenerateM1M2M3(&she,
              uid, WC_SHE_UID_SZ,
              authKeyId, authKey, WC_SHE_KEY_SZ,
              targetKeyId, newKey, WC_SHE_KEY_SZ,
              counter, flags,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ);
    \endcode

    \sa wc_SHE_GenerateM4M5
    \sa wc_SHE_ImportM1M2M3
    \sa wc_SHE_LoadKey
*/
int wc_SHE_GenerateM1M2M3(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, const byte* authKey, word32 authKeySz,
                      byte targetKeyId, const byte* newKey, word32 newKeySz,
                      word32 counter, byte flags,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz);

/*!
    \ingroup SHE
    \brief SHEの検証メッセージM4とM5を生成し、呼び出し側が用意したバッファへ書き込みます。新しい鍵からK3とK4を導出するためにMiyaguchi-Preneel AES-128 KDFを、M4のカウンタブロックにAES-ECBを、M5にAES-CMACを使用します。M1/M2/M3とは独立しており、別のコンテキストで呼び出すこともできます。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、サイズが正しくない場合、またはcounter、authKeyId、targetKeyIdがパックされるフィールドの幅を超える場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param uid 15バイトのSHE UID(M1で使用したものと同じUID)
    \param uidSz WC_SHE_UID_SZ(15)でなければなりません
    \param authKeyId 認可鍵の4ビットのスロットID(M1と同じ)
    \param targetKeyId ロード対象の鍵の4ビットのスロットID(M1と同じ)
    \param newKey 新しい鍵の16バイトの値
    \param newKeySz WC_SHE_KEY_SZ(16)でなければなりません
    \param counter 28ビットの単調増加カウンタ(M2と同じ値)
    \param m4 M4の出力バッファ(32バイト)
    \param m4Sz m4バッファのサイズ。WC_SHE_M4_SZ以上でなければなりません
    \param m5 M5の出力バッファ(16バイト)
    \param m5Sz m5バッファのサイズ。WC_SHE_M5_SZ以上でなければなりません

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_GenerateM4M5(&she,
              uid, WC_SHE_UID_SZ,
              authKeyId, targetKeyId,
              newKey, WC_SHE_KEY_SZ,
              counter,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_GenerateM1M2M3
    \sa wc_SHE_LoadKey_Verify
*/
int wc_SHE_GenerateM4M5(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, byte targetKeyId,
                      const byte* newKey, word32 newKeySz,
                      word32 counter,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief Init、ImportM1M2M3、GenerateM4M5(コールバック経由)、Freeを一括で行う便利なラッパーです。M1/M2/M3をHSMへ送信してM4/M5を受け取るハードウェア暗号コールバックにディスパッチします。有効なdevId(INVALID_DEVIDではない値)が必要です。コンパイル対象から除外するにはNO_WC_SHE_LOADKEYを定義してください。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはサイズが正しくない場合に返されます

    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID(INVALID_DEVIDであってはなりません)
    \param m1 16バイトのM1入力メッセージ
    \param m1Sz WC_SHE_M1_SZ(16)でなければなりません
    \param m2 32バイトのM2入力メッセージ
    \param m2Sz WC_SHE_M2_SZ(32)でなければなりません
    \param m3 16バイトのM3入力メッセージ
    \param m3Sz WC_SHE_M3_SZ(16)でなければなりません
    \param m4 M4の出力バッファ(32バイト)
    \param m4Sz m4バッファのサイズ。WC_SHE_M4_SZ以上でなければなりません
    \param m5 M5の出力バッファ(16バイト)
    \param m5Sz m5バッファのサイズ。WC_SHE_M5_SZ以上でなければなりません

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey(NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey_Id
    \sa wc_SHE_LoadKey_Label
    \sa wc_SHE_LoadKey_Verify
    \sa wc_SHE_ImportM1M2M3
    \sa wc_SHE_GenerateM4M5
*/
int wc_SHE_LoadKey(
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief 不透明なハードウェア鍵識別子を指定して鍵ロードを一括で行います。wc_SHE_LoadKeyと同じですが、コンテキストの初期化にwc_SHE_Init_Idを使用します。コンパイル対象から除外するにはNO_WC_SHE_LOADKEYを定義してください。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはサイズが正しくない場合に返されます

    \param id 不透明な鍵識別子のバイト列
    \param idLen idのバイト単位の長さ
    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID(INVALID_DEVIDであってはなりません)
    \param m1 16バイトのM1入力メッセージ
    \param m1Sz WC_SHE_M1_SZ(16)でなければなりません
    \param m2 32バイトのM2入力メッセージ
    \param m2Sz WC_SHE_M2_SZ(32)でなければなりません
    \param m3 16バイトのM3入力メッセージ
    \param m3Sz WC_SHE_M3_SZ(16)でなければなりません
    \param m4 M4の出力バッファ(32バイト)
    \param m4Sz m4バッファのサイズ。WC_SHE_M4_SZ以上でなければなりません
    \param m5 M5の出力バッファ(16バイト)
    \param m5Sz m5バッファのサイズ。WC_SHE_M5_SZ以上でなければなりません

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    unsigned char keyId[] = { 0x01, 0x02 };
    int ret;
    ret = wc_SHE_LoadKey_Id(keyId, sizeof(keyId), NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey
    \sa wc_SHE_LoadKey_Label
    \sa wc_SHE_LoadKey_Verify_Id
*/
int wc_SHE_LoadKey_Id(
    unsigned char* id, int idLen,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief 人間が読める鍵ラベルを指定して鍵ロードを一括で行います。wc_SHE_LoadKeyと同じですが、コンテキストの初期化にwc_SHE_Init_Labelを使用します。コンパイル対象から除外するにはNO_WC_SHE_LOADKEYを定義してください。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはサイズが正しくない場合に返されます

    \param label NUL終端された鍵ラベル文字列
    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID(INVALID_DEVIDであってはなりません)
    \param m1 16バイトのM1入力メッセージ
    \param m1Sz WC_SHE_M1_SZ(16)でなければなりません
    \param m2 32バイトのM2入力メッセージ
    \param m2Sz WC_SHE_M2_SZ(32)でなければなりません
    \param m3 16バイトのM3入力メッセージ
    \param m3Sz WC_SHE_M3_SZ(16)でなければなりません
    \param m4 M4の出力バッファ(32バイト)
    \param m4Sz m4バッファのサイズ。WC_SHE_M4_SZ以上でなければなりません
    \param m5 M5の出力バッファ(16バイト)
    \param m5Sz m5バッファのサイズ。WC_SHE_M5_SZ以上でなければなりません

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey_Label("ecu-master", NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey
    \sa wc_SHE_LoadKey_Id
    \sa wc_SHE_LoadKey_Verify_Label
*/
int wc_SHE_LoadKey_Label(
    const char* label,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief M4/M5の検証を伴う一括の鍵ロードです。wc_SHE_LoadKeyと同じですが、HSMが返したM4/M5を、呼び出し側が用意した期待値と一定時間で比較して照合します。不一致の場合はSIG_VERIFY_Eを返します。失敗した場合でも、実際のM4/M5は出力バッファへ書き込まれます。コンパイル対象から除外するにはNO_WC_SHE_LOADKEYを定義してください。

    \return 0 成功した場合に返されます
    \return SIG_VERIFY_E M4/M5が期待値と一致しない場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはサイズが正しくない場合に返されます

    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID(INVALID_DEVIDであってはなりません)
    \param m1 16バイトのM1入力メッセージ
    \param m1Sz WC_SHE_M1_SZ(16)でなければなりません
    \param m2 32バイトのM2入力メッセージ
    \param m2Sz WC_SHE_M2_SZ(32)でなければなりません
    \param m3 16バイトのM3入力メッセージ
    \param m3Sz WC_SHE_M3_SZ(16)でなければなりません
    \param m4 M4の出力バッファ(32バイト)
    \param m4Sz m4バッファのサイズ。WC_SHE_M4_SZ以上でなければなりません
    \param m5 M5の出力バッファ(16バイト)
    \param m5Sz m5バッファのサイズ。WC_SHE_M5_SZ以上でなければなりません
    \param m4Expected 照合に使用するM4検証メッセージの期待値
    \param m4ExpectedSz WC_SHE_M4_SZ(32)でなければなりません
    \param m5Expected 照合に使用するM5検証メッセージの期待値
    \param m5ExpectedSz WC_SHE_M5_SZ(16)でなければなりません

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey_Verify(NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ,
              expectedM4, WC_SHE_M4_SZ,
              expectedM5, WC_SHE_M5_SZ);
    if (ret == SIG_VERIFY_E) {
        // M4/M5の不一致
    }
    \endcode

    \sa wc_SHE_LoadKey
    \sa wc_SHE_LoadKey_Verify_Id
    \sa wc_SHE_LoadKey_Verify_Label
*/
int wc_SHE_LoadKey_Verify(
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz);

/*!
    \ingroup SHE
    \brief 不透明な鍵識別子とM4/M5の検証を伴う一括の鍵ロードです。wc_SHE_LoadKey_Idとwc_SHE_LoadKey_Verifyを組み合わせたものです。コンパイル対象から除外するにはNO_WC_SHE_LOADKEYを定義してください。

    \return 0 成功した場合に返されます
    \return SIG_VERIFY_E M4/M5が期待値と一致しない場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはサイズが正しくない場合に返されます

    \param id 不透明な鍵識別子のバイト列
    \param idLen idのバイト単位の長さ
    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID(INVALID_DEVIDであってはなりません)
    \param m1 16バイトのM1入力メッセージ
    \param m1Sz WC_SHE_M1_SZ(16)でなければなりません
    \param m2 32バイトのM2入力メッセージ
    \param m2Sz WC_SHE_M2_SZ(32)でなければなりません
    \param m3 16バイトのM3入力メッセージ
    \param m3Sz WC_SHE_M3_SZ(16)でなければなりません
    \param m4 M4の出力バッファ(32バイト)
    \param m4Sz m4バッファのサイズ。WC_SHE_M4_SZ以上でなければなりません
    \param m5 M5の出力バッファ(16バイト)
    \param m5Sz m5バッファのサイズ。WC_SHE_M5_SZ以上でなければなりません
    \param m4Expected M4検証メッセージの期待値
    \param m4ExpectedSz WC_SHE_M4_SZ(32)でなければなりません
    \param m5Expected M5検証メッセージの期待値
    \param m5ExpectedSz WC_SHE_M5_SZ(16)でなければなりません

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    unsigned char keyId[] = { 0x01, 0x02 };
    int ret;
    ret = wc_SHE_LoadKey_Verify_Id(keyId, sizeof(keyId), NULL, myDevId,
              m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ,
              expectedM4, WC_SHE_M4_SZ, expectedM5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey_Id
    \sa wc_SHE_LoadKey_Verify
    \sa wc_SHE_LoadKey_Verify_Label
*/
int wc_SHE_LoadKey_Verify_Id(
    unsigned char* id, int idLen,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz);

/*!
    \ingroup SHE
    \brief 鍵ラベルとM4/M5の検証を伴う一括の鍵ロードです。wc_SHE_LoadKey_Labelとwc_SHE_LoadKey_Verifyを組み合わせたものです。コンパイル対象から除外するにはNO_WC_SHE_LOADKEYを定義してください。

    \return 0 成功した場合に返されます
    \return SIG_VERIFY_E M4/M5が期待値と一致しない場合に返されます
    \return BAD_FUNC_ARG 必要なポインタのいずれかがNULLの場合、またはサイズが正しくない場合に返されます

    \param label NUL終端された鍵ラベル文字列
    \param heap 内部のメモリ確保に使用するヒープヒント、またはNULL
    \param devId 暗号コールバックのデバイスID(INVALID_DEVIDであってはなりません)
    \param m1 16バイトのM1入力メッセージ
    \param m1Sz WC_SHE_M1_SZ(16)でなければなりません
    \param m2 32バイトのM2入力メッセージ
    \param m2Sz WC_SHE_M2_SZ(32)でなければなりません
    \param m3 16バイトのM3入力メッセージ
    \param m3Sz WC_SHE_M3_SZ(16)でなければなりません
    \param m4 M4の出力バッファ(32バイト)
    \param m4Sz m4バッファのサイズ。WC_SHE_M4_SZ以上でなければなりません
    \param m5 M5の出力バッファ(16バイト)
    \param m5Sz m5バッファのサイズ。WC_SHE_M5_SZ以上でなければなりません
    \param m4Expected M4検証メッセージの期待値
    \param m4ExpectedSz WC_SHE_M4_SZ(32)でなければなりません
    \param m5Expected M5検証メッセージの期待値
    \param m5ExpectedSz WC_SHE_M5_SZ(16)でなければなりません

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey_Verify_Label("ecu-master", NULL, myDevId,
              m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ,
              expectedM4, WC_SHE_M4_SZ, expectedM5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey_Label
    \sa wc_SHE_LoadKey_Verify
    \sa wc_SHE_LoadKey_Verify_Id
*/
int wc_SHE_LoadKey_Verify_Label(
    const char* label,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz);

/*!
    \ingroup SHE
    \brief ハードウェアから鍵をSHEのロード可能な形式(M1〜M5)でエクスポートします。一部のHSMでは特定の鍵スロット(例: RAM鍵)のエクスポートが許可されており、後からSHEの鍵更新プロトコルで再ロードできます。WOLF_CRYPTO_CBが有効で、かつNO_WC_SHE_EXPORTKEYが定義されていないことが必要です。出力バッファはいずれもNULLにでき、その場合そのメッセージはスキップされます。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG sheがNULLの場合に返されます
    \return CRYPTOCB_UNAVAILABLE コールバックが登録されていない場合に返されます

    \param she 初期化済みのSHEコンテキスト
    \param m1 M1の出力バッファ(16バイト)、スキップする場合はNULL
    \param m1Sz m1バッファのサイズ
    \param m2 M2の出力バッファ(32バイト)、スキップする場合はNULL
    \param m2Sz m2バッファのサイズ
    \param m3 M3の出力バッファ(16バイト)、スキップする場合はNULL
    \param m3Sz m3バッファのサイズ
    \param m4 M4の出力バッファ(32バイト)、スキップする場合はNULL
    \param m4Sz m4バッファのサイズ
    \param m5 M5の出力バッファ(16バイト)、スキップする場合はNULL
    \param m5Sz m5バッファのサイズ
    \param ctx コールバックに渡される読み取り専用の呼び出し側コンテキスト

    _Example_
    \code
    byte m1[WC_SHE_M1_SZ], m2[WC_SHE_M2_SZ], m3[WC_SHE_M3_SZ];
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_ExportKey(&she,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ,
              NULL);
    \endcode

    \sa wc_SHE_ImportM1M2M3
    \sa wc_SHE_LoadKey
*/
int wc_SHE_ExportKey(wc_SHE* she,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz,
                      const void* ctx);

/*!
    \ingroup SHE
    \brief Miyaguchi-Preneel AES-128一方向圧縮関数です。H_0 = 0、H_i = E_{H_{i-1}}(M_i) XOR M_i XOR H_{i-1}。鍵サイズがブロックサイズと等しいAES-128でのみ使用できます。テスト目的で公開している内部関数です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG いずれかのポインタがNULLの場合に返されます

    \param aes 呼び出し側が所有する初期化済みのAes構造体
    \param in 入力データ(例: BaseKey || KDF_Constant、32バイト)
    \param inSz 入力のバイト単位の長さ(ブロック境界までゼロパディングされます)
    \param out 16バイトの圧縮結果を受け取る出力バッファ

    _Example_
    \code
    Aes aes;
    byte input[32] = { ... };
    byte output[WC_SHE_KEY_SZ];
    int ret;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    ret = wc_SHE_AesMp16(&aes, input, sizeof(input), output);
    wc_AesFree(&aes);
    \endcode

    \sa wc_SHE_GenerateM1M2M3
    \sa wc_SHE_GenerateM4M5
*/
int wc_SHE_AesMp16(Aes* aes, const byte* in, word32 inSz,
                     byte* out);
