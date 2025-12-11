/*!
    \ingroup AES
    \brief この関数は、キーを設定し、初期化ベクトルを設定することでAES構造体を初期化します。

    \return 0 キーと初期化ベクトルの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG キーの長さが無効な場合に返されます。

    \param aes 変更するAES構造体へのポインタ
    \param key 暗号化と復号のための16、24、または32バイトの秘密鍵
    \param len 渡されたキーの長さ
    \param iv キーの初期化に使用される初期化ベクトルへのポインタ
    \param dir 暗号の方向。暗号化する場合はAES_ENCRYPTIONを設定し、復号する場合はAES_DECRYPTIONを設定します。一部のモード（CFBおよびCTR）の方向は常にAES_ENCRYPTIONです。

    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { 16、24、または32バイトのキー };
    byte iv[]  = { 16バイトのiv };
    if (ret = wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID) != 0) {
        // aes keyの初期化に失敗
    }
    if (ret = wc_AesSetKey(&enc, key, AES_BLOCK_SIZE, iv,
    AES_ENCRYPTION) != 0) {
	// aes keyの設定に失敗
    }
    \endcode

    \sa wc_AesSetKeyDirect
    \sa wc_AesSetIV
*/
int  wc_AesSetKey(Aes* aes, const byte* key, word32 len,
                              const byte* iv, int dir);

/*!
    \ingroup AES
    \brief この関数は、特定のAESオブジェクトの初期化ベクトルを設定します。この関数を呼び出す前にAESオブジェクトを初期化する必要があります。

    \return 0 初期化ベクトルの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG AESポインタがNULLの場合に返されます。

    \param aes 初期化ベクトルを設定するAES構造体へのポインタ
    \param iv AES構造体を初期化するために使用される初期化ベクトル。値がNULLの場合、デフォルトの動作はivを0に初期化します。

    _Example_
    \code
    Aes enc;
    // enc keyを設定
    byte iv[]  = { 16バイトのiv };
    if (ret = wc_AesSetIV(&enc, iv) != 0) {
	// aes ivの設定に失敗
    }
    \endcode

    \sa wc_AesSetKeyDirect
    \sa wc_AesSetKey
*/
int  wc_AesSetIV(Aes* aes, const byte* iv);

/*!
    \ingroup AES
    \brief 入力バッファinから平文メッセージを暗号化し、AESを使用した暗号ブロック連鎖により結果の暗号文を出力バッファoutに格納します。この関数は、メッセージを暗号化する前にAesSetKeyを呼び出してAESオブジェクトが初期化されている必要があります。この関数は、入力メッセージがAESブロック長に整列していることを前提としており、入力長がブロック長の倍数であることを期待します。ビルド構成でWOLFSSL_AES_CBC_LENGTH_CHECKSが定義されている場合、これはオプションでチェックおよび強制されます。ブロック倍数の入力を保証するために、事前にPKCS#7スタイルのパディングを追加する必要があります。これは、自動的にパディングを追加するOpenSSLのAES-CBCメソッドとは異なります。wolfSSLと対応するOpenSSL関数を相互運用させるには、OpenSSLコマンドライン関数で-nopadオプションを指定して、wolfSSLのAesCbcEncryptメソッドのように動作し、暗号化中に余分なパディングを追加しないようにする必要があります。

    \return 0 メッセージの暗号化に成功した場合に返されます。
    \return BAD_ALIGN_E ブロック整列エラーで返される場合があります。
    \return BAD_LENGTH_E ライブラリがWOLFSSL_AES_CBC_LENGTH_CHECKSでビルドされている場合、入力長がAESブロック長の倍数でない場合に返されます。

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param out 暗号化されたメッセージの暗号文を格納する出力バッファへのポインタ
    \param in 暗号化されるメッセージを含む入力バッファへのポインタ
    \param sz 入力メッセージのサイズ

    _Example_
    \code
    Aes enc;
    int ret = 0;
    // wc_AesInitとwc_AesSetKeyを使用してencを初期化、方向は
    // AES_ENCRYPTIONを使用
    byte msg[AES_BLOCK_SIZE * n]; // 16バイトの倍数
    // msgにデータを入力
    byte cipher[AES_BLOCK_SIZE * n]; // 16バイトの倍数
    if ((ret = wc_AesCbcEncrypt(&enc, cipher, message, sizeof(msg))) != 0 ) {
	// ブロック整列エラー
    }
    \endcode

    \sa wc_AesInit
    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesCbcDecrypt
*/
int  wc_AesCbcEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief 入力バッファinから暗号を復号し、AESを使用した暗号ブロック連鎖により結果の平文を出力バッファoutに格納します。この関数は、メッセージを復号する前にAesSetKeyを呼び出してAES構造体が初期化されている必要があります。この関数は、元のメッセージがAESブロック長に整列していたことを前提としており、入力長がブロック長の倍数であることを期待します。ビルド構成でWOLFSSL_AES_CBC_LENGTH_CHECKSが定義されている場合、これはオプションでチェックおよび強制されます。これは、PKCS#7パディングを自動的に追加するOpenSSLのAES-CBCメソッドとは異なり、ブロック倍数の入力を必要としません。wolfSSL関数と同等のOpenSSL関数を相互運用させるには、OpenSSLコマンドライン関数で-nopadオプションを指定して、wolfSSLのAesCbcEncryptメソッドのように動作し、復号中にエラーを発生させないようにする必要があります。

    \return 0 メッセージの復号に成功した場合に返されます。
    \return BAD_ALIGN_E ブロック整列エラーで返される場合があります。
    \return BAD_LENGTH_E ライブラリがWOLFSSL_AES_CBC_LENGTH_CHECKSでビルドされている場合、入力長がAESブロック長の倍数でない場合に返されます。

    \param aes データを復号するために使用されるAESオブジェクトへのポインタ。
    \param out 復号されたメッセージの平文を格納する出力バッファへのポインタ。
    サイズはAES_BLOCK_LENGTHの倍数である必要があり、必要に応じてパディングされます
    \param in 復号される暗号文を含む入力バッファへのポインタ。
    サイズはAES_BLOCK_LENGTHの倍数である必要があり、必要に応じてパディングされます
    \param sz 入力メッセージのサイズ。

    _Example_
    \code
    Aes dec;
    int ret = 0;
    // wc_AesInitとwc_AesSetKeyを使用してdecを初期化、方向は
    // AES_DECRYPTIONを使用
    byte cipher[AES_BLOCK_SIZE * n]; // 16バイトの倍数
    // cipherに暗号文を入力
    byte plain [AES_BLOCK_SIZE * n];
    if ((ret = wc_AesCbcDecrypt(&dec, plain, cipher, sizeof(cipher))) != 0 ) {
	// ブロック整列エラー
    }
    \endcode

    \sa wc_AesInit
    \sa wc_AesSetKey
    \sa wc_AesCbcEncrypt
*/
int  wc_AesCbcDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief AESを使用したCTRモードで、入力バッファinからメッセージを暗号化/復号し、結果の暗号文を出力バッファoutに格納します。この関数は、コンパイル時にWOLFSSL_AES_COUNTERが有効になっている場合のみ有効です。この関数を呼び出す前に、AesSetKeyを介してAES構造体を初期化する必要があります。この関数は復号と暗号化の両方に使用されることに注意してください。注：暗号化と復号に同じAPIを使用することについて。ユーザは暗号化/復号用のAes構造体を区別する必要があります。

    \return int wolfSSLエラーまたは成功ステータスに対応する整数値

    \param aes データを復号するために使用されるAESオブジェクトへのポインタ
    \param out 暗号化されたメッセージの暗号文を格納する出力バッファへのポインタ
    サイズはAES_BLOCK_LENGTHの倍数である必要があり、必要に応じてパディングされます
    \param in 暗号化される平文を含む入力バッファへのポインタ
    サイズはAES_BLOCK_LENGTHの倍数である必要があり、必要に応じてパディングされます
    \param sz 入力平文のサイズ

    _Example_
    \code
    Aes enc;
    Aes dec;
    // wc_AesInitとwc_AesSetKeyDirectを使用してencとdecを初期化、方向は
    // AES_ENCRYPTIONを使用。基盤となるAPIは暗号化のみを呼び出し、
    // デフォルトで暗号に対して暗号化を呼び出すと暗号の復号が
    // 行われるため

    byte msg[AES_BLOCK_SIZE * n]; // nは正の整数で、msgを
    16バイトの倍数にする
    // plainにメッセージテキストを入力
    byte cipher[AES_BLOCK_SIZE * n];
    byte decrypted[AES_BLOCK_SIZE * n];
    wc_AesCtrEncrypt(&enc, cipher, msg, sizeof(msg)); // plainを暗号化
    wc_AesCtrEncrypt(&dec, decrypted, cipher, sizeof(cipher));
    // 暗号文を復号
    \endcode

    \sa wc_AesSetKey
*/
int wc_AesCtrEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief この関数は、入力ブロックinの1ブロック暗号化を出力ブロックoutに行います。提供されたAES構造体のキーを使用し、この関数を呼び出す前にwc_AesSetKeyで初期化する必要があります。wc_AesSetKeyはivをNULLに設定して呼び出す必要があります。これは、構成オプションWOLFSSL_AES_DIRECTが有効になっている場合のみ有効です。警告：ほぼすべてのユースケースで、ECBモードは安全性が低いと考えられています。可能な限りECB APIを直接使用することは避けてください。

    \return int wolfSSLエラーまたは成功ステータスに対応する整数値

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param out 暗号化されたメッセージの暗号文を格納する出力バッファへのポインタ
    \param in 暗号化される平文を含む入力バッファへのポインタ

    _Example_
    \code
    Aes enc;
    // wc_AesInitとwc_AesSetKeyを使用してencを初期化、方向は
    // AES_ENCRYPTIONを使用
    byte msg [AES_BLOCK_SIZE]; // 16バイト
    // msgを暗号化する平文で初期化
    byte cipher[AES_BLOCK_SIZE];
    wc_AesEncryptDirect(&enc, cipher, msg);
    \endcode

    \sa wc_AesDecryptDirect
    \sa wc_AesSetKeyDirect
*/
int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in);

/*!
    \ingroup AES
    \brief この関数は、入力ブロックinの1ブロック復号を出力ブロックoutに行います。提供されたAES構造体のキーを使用し、この関数を呼び出す前にwc_AesSetKeyで初期化する必要があります。wc_AesSetKeyはivをNULLに設定して呼び出す必要があります。これは、構成オプションWOLFSSL_AES_DIRECTが有効になっている場合のみ有効です。警告：ほぼすべてのユースケースで、ECBモードは安全性が低いと考えられています。可能な限りECB APIを直接使用することは避けてください。

    \return int wolfSSLエラーまたは成功ステータスに対応する整数値

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param out 復号された暗号文の平文を格納する出力バッファへのポインタ
    \param in 復号される暗号文を含む入力バッファへのポインタ

    _Example_
    \code
    Aes dec;
    // wc_AesInitとwc_AesSetKeyを使用してencを初期化、方向は
    // AES_DECRYPTIONを使用
    byte cipher [AES_BLOCK_SIZE]; // 16バイト
    // cipherを復号する暗号文で初期化
    byte msg[AES_BLOCK_SIZE];
    wc_AesDecryptDirect(&dec, msg, cipher);
    \endcode

    \sa wc_AesEncryptDirect
    \sa wc_AesSetKeyDirect
 */
int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in);

/*!
    \ingroup AES
    \brief この関数は、AESを使用したCTRモードのAESキーを設定するために使用されます。指定されたキー、iv（初期化ベクトル）、および暗号化dir（方向）でAESオブジェクトを初期化します。構成オプションWOLFSSL_AES_DIRECTが有効になっている場合のみ有効です。現在、wc_AesSetKeyDirectは内部的にwc_AesSetKeyを使用しています。警告：ほぼすべてのユースケースで、ECBモードは安全性が低いと考えられています。可能な限りECB APIを直接使用することは避けてください。

    \return 0 キーの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 指定されたキーの長さが無効な場合に返されます。

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param key 暗号化と復号のための16、24、または32バイトの秘密鍵
    \param len 渡されたキーの長さ
    \param iv キーの初期化に使用される初期化ベクトル
    \param dir 暗号の方向。暗号化する場合はAES_ENCRYPTIONを設定し、復号する場合はAES_DECRYPTIONを設定します。（wolfssl/wolfcrypt/aes.hの列挙型を参照）（注：Aesカウンタモード（ストリーム暗号）でwc_AesSetKeyDirectを使用する場合、暗号化と復号の両方にAES_ENCRYPTIONのみを使用）

    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { 16、24、または32バイトのキー };
    byte iv[]  = { 16バイトのiv };

    if (ret = wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID) != 0) {
        // aes keyの初期化に失敗
    }
    if (ret = wc_AesSetKeyDirect(&enc, key, sizeof(key), iv,
    AES_ENCRYPTION) != 0) {
	// aes keyの設定に失敗
    }
    \endcode

    \sa wc_AesEncryptDirect
    \sa wc_AesDecryptDirect
    \sa wc_AesSetKey
*/
int  wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
                                const byte* iv, int dir);

/*!
    \ingroup AES
    \brief この関数は、AES GCM（Galois/Counter Mode）のキーを設定するために使用されます。指定されたキーでAESオブジェクトを初期化します。コンパイル時に構成オプションHAVE_AESGCMが有効になっている場合のみ有効です。

    \return 0 キーの設定に成功した場合に返されます。
    \return BAD_FUNC_ARG 指定されたキーの長さが無効な場合に返されます。

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param key 暗号化と復号のための16、24、または32バイトの秘密鍵
    \param len 渡されたキーの長さ

    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { 16、24、32バイトのキー };
    if (ret = wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID) != 0) {
        // aes keyの初期化に失敗
    }
    if (ret = wc_AesGcmSetKey(&enc, key, sizeof(key)) != 0) {
	// aes keyの設定に失敗
    }
    \endcode

    \sa wc_AesGcmEncrypt
    \sa wc_AesGcmDecrypt
*/
int  wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len);

/*!
    \ingroup AES
    \brief この関数は、バッファinに保持されている入力メッセージを暗号化し、結果の暗号文を出力バッファoutに格納します。暗号化の呼び出しごとに新しいiv（初期化ベクトル）が必要です。また、入力認証ベクトルauthInを認証タグauthTagにエンコードします。

    \return 0 入力メッセージの暗号化に成功した場合に返されます

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param out 暗号文を格納する出力バッファへのポインタ
    サイズはinのサイズ（sz）と一致する必要があります
    \param in 暗号化するメッセージを保持する入力バッファへのポインタ
    サイズはAES_BLOCK_LENGTHの倍数である必要があり、必要に応じてパディングされます
    \param sz 暗号化する入力メッセージの長さ
    \param iv 初期化ベクトルを含むバッファへのポインタ
    \param ivSz 初期化ベクトルの長さ
    \param authTag 認証タグを格納するバッファへのポインタ
    \param authTagSz 希望する認証タグの長さ
    \param authIn 入力認証ベクトルを含むバッファへのポインタ
    \param authInSz 入力認証ベクトルの長さ

    _Example_
    \code
    Aes enc;
    // wc_AesInit()とwc_AesGcmSetKeyを呼び出してAes構造体を初期化

    byte plain[AES_BLOCK_LENGTH * n]; // nは正の整数で
    plainを16バイトの倍数にする
    // plainを暗号化するメッセージで初期化
    byte cipher[sizeof(plain)];
    byte iv[] = // 16バイトのiv
    byte authTag[AUTH_TAG_LENGTH];
    byte authIn[] = // 認証ベクトル

    wc_AesGcmEncrypt(&enc, cipher, plain, sizeof(cipher), iv, sizeof(iv),
		authTag, sizeof(authTag), authIn, sizeof(authIn));
    \endcode

    \sa wc_AesGcmSetKey
    \sa wc_AesGcmDecrypt
*/
int  wc_AesGcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief この関数は、バッファinに保持されている入力暗号文を復号し、結果のメッセージテキストを出力バッファoutに格納します。また、入力認証ベクトルauthInを、提供された認証タグauthTagと照合してチェックします。ゼロ以外のエラーコードが返された場合、出力データは未定義です。ただし、呼び出し元は平文データの漏洩を防ぐために、無条件に出力バッファをゼロ化する必要があります。

    \return 0 入力メッセージの復号と認証に成功した場合に返されます
    \return AES_GCM_AUTH_E 認証タグが提供された認証コードベクトルauthTagと一致しない場合に返されます。

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param out メッセージテキストを格納する出力バッファへのポインタ
    サイズはinのサイズ（sz）と一致する必要があります
    \param in 復号する暗号文を保持する入力バッファへのポインタ
    サイズはAES_BLOCK_LENGTHの倍数である必要があり、必要に応じてパディングされます
    \param sz 復号する暗号文の長さ
    \param iv 初期化ベクトルを含むバッファへのポインタ
    \param ivSz 初期化ベクトルの長さ
    \param authTag 認証タグを含むバッファへのポインタ
    \param authTagSz 希望する認証タグの長さ
    \param authIn 入力認証ベクトルを含むバッファへのポインタ
    \param authInSz 入力認証ベクトルの長さ

    _Example_
    \code
    Aes enc; // wc_AesGcmEncryptに渡されたものと同じ構造体を使用可能
    // まだ完了していない場合は、wc_AesInitとwc_AesGcmSetKeyを呼び出して
    // aes構造体を初期化

    byte cipher[AES_BLOCK_LENGTH * n]; // nは正の整数で
    cipherを16バイトの倍数にする
    // cipherを復号する暗号文で初期化
    byte output[sizeof(cipher)];
    byte iv[] = // 16バイトのiv
    byte authTag[AUTH_TAG_LENGTH];
    byte authIn[] = // 認証ベクトル

    wc_AesGcmDecrypt(&enc, output, cipher, sizeof(cipher), iv, sizeof(iv),
		authTag, sizeof(authTag), authIn, sizeof(authIn));
    \endcode

    \sa wc_AesGcmSetKey
    \sa wc_AesGcmEncrypt
*/
int  wc_AesGcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief この関数は、Galoisメッセージ認証に使用されるGMACオブジェクトのキーを初期化および設定します。

    \return 0 キーの設定に成功した場合に返されます
    \return BAD_FUNC_ARG キーの長さが無効な場合に返されます。

    \param gmac 認証に使用されるgmacオブジェクトへのポインタ
    \param key 認証のための16、24、または32バイトの秘密鍵
    \param len キーの長さ

    _Example_
    \code
    Gmac gmac;
    key[] = { 16、24、または32バイト長のキー };
    wc_AesInit(gmac.aes, HEAP_HINT, INVALID_DEVID); // devIdが更新されていることを確認
    wc_GmacSetKey(&gmac, key, sizeof(key));
    \endcode

    \sa wc_GmacUpdate
    \sa wc_AesInit
*/
int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len);

/*!
    \ingroup AES
    \brief この関数は、authIn入力のGmacハッシュを生成し、結果をauthTagバッファに格納します。wc_GmacUpdateを実行した後、生成されたauthTagを既知の認証タグと比較して、メッセージの真正性を検証する必要があります。

    \return 0 Gmacハッシュの計算に成功した場合に返されます。

    \param gmac 認証に使用されるgmacオブジェクトへのポインタ
    \param iv ハッシュに使用される初期化ベクトル
    \param ivSz 使用される初期化ベクトルのサイズ
    \param authIn 検証する認証ベクトルを含むバッファへのポインタ
    \param authInSz 認証ベクトルのサイズ
    \param authTag Gmacハッシュを格納する出力バッファへのポインタ
    \param authTagSz Gmacハッシュを格納するために使用される出力バッファのサイズ

    _Example_
    \code
    Gmac gmac;
    key[] = { 16、24、または32バイト長のキー };
    iv[] = { 16バイト長のiv };

    wc_AesInit(gmac.aes, HEAP_HINT, INVALID_DEVID); // devIdが更新されていることを確認
    wc_GmacSetKey(&gmac, key, sizeof(key));
    authIn[] = { 16バイトの認証入力 };
    tag[AES_BLOCK_SIZE]; // 認証コードを格納

    wc_GmacUpdate(&gmac, iv, sizeof(iv), authIn, sizeof(authIn), tag,
    sizeof(tag));
    \endcode

    \sa wc_GmacSetKey
    \sa wc_AesInit
*/
int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                               const byte* authIn, word32 authInSz,
                               byte* authTag, word32 authTagSz);

/*!
    \ingroup AES
    \brief この関数は、CCM（Counter with CBC-MAC）を使用してAESオブジェクトのキーを設定します。AES構造体へのポインタを受け取り、提供されたキーで初期化します。

    \return none

    \param aes 提供されたキーを格納するaes構造体
    \param key 暗号化と復号のための16、24、または32バイトの秘密鍵
    \param keySz 提供されたキーのサイズ

    _Example_
    \code
    Aes enc;
    key[] = { 16、24、または32バイト長のキー };

    wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID); // devIdが更新されていることを確認
    wc_AesCcmSetKey(&enc, key, sizeof(key));
    \endcode

    \sa wc_AesCcmEncrypt
    \sa wc_AesCcmDecrypt
*/
int  wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz);

/*!
    \ingroup AES

    \brief この関数は、CCM（Counter with CBC-MAC）を使用して、入力メッセージinを出力バッファoutに暗号化します。その後、authIn入力から認証タグauthTagを計算して格納します。

    \return none

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param out 暗号文を格納する出力バッファへのポインタ
    \param in 暗号化するメッセージを保持する入力バッファへのポインタ
    \param sz 暗号化する入力メッセージの長さ
    \param nonce ナンス（1回のみ使用される数値）を含むバッファへのポインタ
    \param nonceSz ナンスの長さ
    \param authTag 認証タグを格納するバッファへのポインタ
    \param authTagSz 希望する認証タグの長さ
    \param authIn 入力認証ベクトルを含むバッファへのポインタ
    \param authInSz 入力認証ベクトルの長さ

    _Example_
    \code
    Aes enc;
    // wc_AesInitとwc_AesCcmSetKeyでencを初期化

    nonce[] = { ナンスを初期化 };
    plain[] = { 平文メッセージ };
    cipher[sizeof(plain)];

    authIn[] = { 16バイトの認証入力 };
    tag[AES_BLOCK_SIZE]; // 認証コードを格納

    wc_AesCcmEncrypt(&enc, cipher, plain, sizeof(plain), nonce, sizeof(nonce),
		tag, sizeof(tag), authIn, sizeof(authIn));
    \endcode

    \sa wc_AesCcmSetKey
    \sa wc_AesCcmDecrypt
*/
int  wc_AesCcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES

    \brief この関数は、CCM（Counter with CBC-MAC）を使用して、入力暗号文inを出力バッファoutに復号します。その後、authIn入力から認証タグauthTagを計算します。ゼロ以外のエラーコードが返された場合、出力データは未定義です。ただし、呼び出し元は平文データの漏洩を防ぐために、無条件に出力バッファをゼロ化する必要があります。

    \return 0 入力メッセージの復号に成功した場合に返されます
    \return AES_CCM_AUTH_E 認証タグが提供された認証コードベクトルauthTagと一致しない場合に返されます。

    \param aes データを暗号化するために使用されるAESオブジェクトへのポインタ
    \param out 暗号文を格納する出力バッファへのポインタ
    \param in 暗号化するメッセージを保持する入力バッファへのポインタ
    \param sz 復号する入力暗号文の長さ
    \param nonce ナンス（1回のみ使用される数値）を含むバッファへのポインタ
    \param nonceSz ナンスの長さ
    \param authTag 認証タグを格納するバッファへのポインタ
    \param authTagSz 希望する認証タグの長さ
    \param authIn 入力認証ベクトルを含むバッファへのポインタ
    \param authInSz 入力認証ベクトルの長さ

    _Example_
    \code
    Aes dec;
    // wc_AesInitとwc_AesCcmSetKeyでdecを初期化

    nonce[] = { ナンスを初期化 };
    cipher[] = { 暗号化されたメッセージ };
    plain[sizeof(cipher)];

    authIn[] = { 16バイトの認証入力 };
    tag[AES_BLOCK_SIZE] = { 検証のために受信した認証タグ };

    int return = wc_AesCcmDecrypt(&dec, plain, cipher, sizeof(cipher),
    nonce, sizeof(nonce),tag, sizeof(tag), authIn, sizeof(authIn));
    if(return != 0) {
	// 復号エラー、無効な認証コード
    }
    \endcode

    \sa wc_AesCcmSetKey
    \sa wc_AesCcmEncrypt
*/
int  wc_AesCcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES

    \brief これはAES-XTSコンテキストを初期化するためのものです。使用が完了したら、ユーザがaesキーに対してwc_AesXtsFreeを呼び出す必要があります。

    \return 0 成功

    \param aes   暗号化/復号プロセスのためのAESキー
    \param heap  メモリに使用するヒープヒント。NULLでも可
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsInit(&aes, NULL, INVALID_DEVID) != 0)
    {
        // エラーを処理
    }
    if(wc_AesXtsSetKeyNoInit(&aes, key, sizeof(key), AES_ENCRYPTION) != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsSetKey
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsFree
*/
int wc_AesXtsInit(XtsAes* aes, void* heap, int devId);


/*!
    \ingroup AES

    \brief これは、最初にwc_AesXtsInit()を呼び出した後、キーを正しい暗号化または復号タイプに設定するのに役立ちます。使用が完了したら、ユーザがaesキーに対してwc_AesXtsFreeを呼び出す必要があります。

    \return 0 成功

    \param aes   暗号化/復号プロセスのためのAESキー
    \param key   aesキー | tweakキーを保持するバッファ
    \param len   キーバッファの長さ（バイト単位）。キーサイズの2倍である必要があります。
                 つまり、16バイトのキーの場合は32です。
    \param dir   方向、AES_ENCRYPTIONまたはAES_DECRYPTION

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsInit(&aes, NULL, 0) != 0)
    {
        // エラーを処理
    }
    if(wc_AesXtsSetKeyNoInit(&aes, key, sizeof(key), AES_ENCRYPTION, NULL, 0)
       != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsFree
*/
int wc_AesXtsSetKeyNoInit(XtsAes* aes, const byte* key,
         word32 len, int dir);


/*!
    \ingroup AES

    \brief これは、キーを正しい暗号化または復号タイプに設定するのに役立ちます。使用が完了したら、ユーザがaesキーに対してwc_AesXtsFreeを呼び出す必要があります。

    \return 0 成功

    \param aes   暗号化/復号プロセスのためのAESキー
    \param key   aesキー | tweakキーを保持するバッファ
    \param len   キーバッファの長さ（バイト単位）。キーサイズの2倍である必要があります。
                 つまり、16バイトのキーの場合は32です。
    \param dir   方向、AES_ENCRYPTIONまたはAES_DECRYPTION
    \param heap  メモリに使用するヒープヒント。NULLでも可
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsSetKey(&aes, key, sizeof(key), AES_ENCRYPTION, NULL, INVALID_DEVID) != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsFree
*/
int wc_AesXtsSetKey(XtsAes* aes, const byte* key,
         word32 len, int dir, void* heap, int devId);

/*!
    \ingroup AES

    \brief wc_AesXtsEncryptと同じプロセスですが、バイト配列の代わりにword64型をtweak値として使用します。これはword64をバイト配列に変換し、wc_AesXtsEncryptを呼び出すだけです。

    \return 0 成功

    \param aes    ブロック暗号化/復号に使用するAESキー
    \param out    暗号文を保持する出力バッファ
    \param in     暗号化する入力平文バッファ
    \param sz     outとinバッファの両方のサイズ
    \param sector tweakに使用する値

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    word64 s = VALUE;

    // AES_ENCRYPTIONをdirとしてキーを設定
    if(wc_AesXtsEncryptSector(&aes, cipher, plain, SIZE, s) != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsEncryptSector(XtsAes* aes, byte* out,
         const byte* in, word32 sz, word64 sector);

/*!
    \ingroup AES

    \brief wc_AesXtsDecryptと同じプロセスですが、バイト配列の代わりにword64型をtweak値として使用します。これはword64をバイト配列に変換するだけです。

    \return 0 成功

    \param aes    ブロック暗号化/復号に使用するAESキー
    \param out    平文を保持する出力バッファ
    \param in     復号する入力暗号文バッファ
    \param sz     outとinバッファの両方のサイズ
    \param sector tweakに使用する値

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    word64 s = VALUE;

    // AES_DECRYPTIONをdirとしてaesキーを設定し、tweakはAES_ENCRYPTIONで設定

    if(wc_AesXtsDecryptSector(&aes, plain, cipher, SIZE, s) != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsDecryptSector(XtsAes* aes, byte* out,
         const byte* in, word32 sz, word64 sector);

/*!
    \ingroup AES

    \brief XTSモードのAES。（XTS）TweakとCipher Text Stealingを使用したXEX暗号化。

    \return 0 成功

    \param aes   ブロック暗号化/復号に使用するAESキー
    \param out   暗号文を保持する出力バッファ
    \param in    暗号化する入力平文バッファ
    \param sz    outとinバッファの両方のサイズ
    \param i     tweakに使用する値
    \param iSz   iバッファのサイズ、常にAES_BLOCK_SIZEである必要がありますが、この入力を持つことで、ユーザが関数を呼び出す方法についてのサニティチェックが追加されます。

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    unsigned char i[AES_BLOCK_SIZE];

    // AES_ENCRYPTIONをdirとしてキーを設定

    if(wc_AesXtsEncrypt(&aes, cipher, plain, SIZE, i, sizeof(i)) != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsEncrypt(XtsAes* aes, byte* out,
         const byte* in, word32 sz, const byte* i, word32 iSz);

/*!
    \ingroup AES

    \brief 暗号化と同じプロセスですが、AesキーはAES_DECRYPTIONタイプです。

    \return 0 成功

    \param aes   ブロック暗号化/復号に使用するAESキー
    \param out   平文を保持する出力バッファ
    \param in    復号する入力暗号文バッファ
    \param sz    outとinバッファの両方のサイズ
    \param i     tweakに使用する値
    \param iSz   iバッファのサイズ、常にAES_BLOCK_SIZEである必要がありますが、この入力を持つことで、ユーザが関数を呼び出す方法についてのサニティチェックが追加されます。

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    unsigned char i[AES_BLOCK_SIZE];

    // AES_DECRYPTIONをdirとしてキーを設定し、tweakはAES_ENCRYPTIONで設定

    if(wc_AesXtsDecrypt(&aes, plain, cipher, SIZE, i, sizeof(i)) != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsDecrypt(XtsAes* aes, byte* out,
        const byte* in, word32 sz, const byte* i, word32 iSz);

/*!
    \ingroup AES

    \brief これは、XtsAes構造体によって使用されるリソースを解放するためのものです

    \return 0 成功

    \param aes 解放するAESキー

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsSetKey(&aes, key, sizeof(key), AES_ENCRYPTION, NULL, 0) != 0)
    {
        // エラーを処理
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
*/
int wc_AesXtsFree(XtsAes* aes);


/*!
    \ingroup AES
    \brief Aes構造体を初期化します。使用するヒープヒントと非同期ハードウェアで使用するIDを設定します。使用が完了したら、ユーザがAes構造体に対してwc_AesFreeを呼び出す必要があります。
    \return 0 成功

    \param aes 初期化するaes構造体
    \param heap 必要に応じてmalloc / freeに使用するヒープヒント
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID（-2）に設定

    _Example_
    \code
    Aes enc;
    void* hint = NULL;
    int devId = INVALID_DEVID; // 非同期を使用しない場合はINVALID_DEVIDがデフォルト

    // 使用する場合はここでヒープヒントを設定可能

    wc_AesInit(&enc, hint, devId);
    \endcode

    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesFree
*/
int  wc_AesInit(Aes* aes, void* heap, int devId);

/*!
    \ingroup AES
    \brief 該当する場合、Aes構造体に関連付けられたリソースを解放します。内部的には時々no-opになることもありますが、新しい環境で使用するためにアプリケーションコードが移植される場合（呼び出しが適用される場合）など、一般的なベストプラクティスとしてすべてのケースで呼び出すことをお勧めします。
    \return no return（void関数）

    \param aes 解放するaes構造体

    _Example_
    \code
    Aes enc;
    void* hint = NULL;
    int devId = INVALID_DEVID; // 非同期を使用しない場合はINVALID_DEVIDがデフォルト

    // 使用する場合はここでヒープヒントを設定可能

    wc_AesInit(&enc, hint, devId);
    // ... 興味深いことをいくつか行う ...
    wc_AesFree(&enc);
    \endcode

    \sa wc_AesInit
*/
int  wc_AesFree(Aes* aes);

/*!
    \ingroup AES

    \brief CFBモードのAES。

    \return 0 成功、失敗時は負のエラー値

    \param aes   ブロック暗号化/復号に使用するAESキー
    \param out   暗号文を保持する出力バッファ（少なくとも入力バッファと同じ大きさである必要があります）
    \param in    暗号化する入力平文バッファ
    \param sz    入力バッファのサイズ

    _Example_
    \code
    Aes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];

    // 暗号化と復号の両方にAES_ENCRYPTIONをdirとしてキーを設定

    if(wc_AesCfbEncrypt(&aes, cipher, plain, SIZE) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_AesCfbDecrypt
    \sa wc_AesSetKey
*/
int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES

    \brief CFBモードのAES。

    \return 0 成功、失敗時は負のエラー値

    \param aes   ブロック暗号化/復号に使用するAESキー
    \param out   復号されたテキストを保持する出力バッファ（少なくとも入力バッファと同じ大きさである必要があります）
    \param in    復号する入力バッファ
    \param sz    入力バッファのサイズ

    _Example_
    \code
    Aes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];

    // 暗号化と復号の両方にAES_ENCRYPTIONをdirとしてキーを設定

    if(wc_AesCfbDecrypt(&aes, plain, cipher, SIZE) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_AesCfbEncrypt
    \sa wc_AesSetKey
*/
int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES

    \brief この関数は、RFC 5297で説明されているSIV（合成初期化ベクトル）暗号化を実行します。

    \return 0 暗号化に成功した場合。
    \return BAD_FUNC_ARG key、SIV、または出力バッファがNULLの場合に返されます。また、キーサイズが32、48、または64バイトでない場合にも返されます。
    \return Other AESまたはCMAC操作が失敗した場合に返されるその他の負のエラー値。

    \param key 使用するキーを含むバイトバッファ。
    \param keySz キーバッファの長さ（バイト単位）。
    \param assoc 追加の認証された関連データ（AD）。
    \param assocSz ADバッファの長さ（バイト単位）。
    \param nonce 1回のみ使用される数値。アルゴリズムによってADと同じ方法で使用されます。
    \param nonceSz nonceバッファの長さ（バイト単位）。
    \param in 暗号化する平文バッファ。
    \param inSz 平文バッファの長さ。
    \param siv S2Vによって出力されるSIV（RFC 5297 2.4を参照）。
    \param out 暗号文を保持するバッファ。平文バッファと同じ長さである必要があります。

    _Example_
    \code
    byte key[] = { 32、48、または64バイトのキー };
    byte assoc[] = {0x01, 0x2, 0x3};
    byte nonce[] = {0x04, 0x5, 0x6};
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte siv[AES_BLOCK_SIZE];
    byte cipherText[sizeof(plainText)];
    if (wc_AesSivEncrypt(key, sizeof(key), assoc, sizeof(assoc), nonce,
        sizeof(nonce), plainText, sizeof(plainText), siv, cipherText) != 0) {
        // 暗号化に失敗
    }
    \endcode

    \sa wc_AesSivDecrypt
*/


int wc_AesSivEncrypt(const byte* key, word32 keySz, const byte* assoc,
                     word32 assocSz, const byte* nonce, word32 nonceSz,
                     const byte* in, word32 inSz, byte* siv, byte* out);

/*!
    \ingroup AES
    \brief この関数は、RFC 5297で説明されているSIV（合成初期化ベクトル）復号を実行します。ゼロ以外のエラーコードが返された場合、出力データは未定義です。ただし、呼び出し元は平文データの漏洩を防ぐために、無条件に出力バッファをゼロ化する必要があります。

    \return 0 復号に成功した場合。
    \return BAD_FUNC_ARG key、SIV、または出力バッファがNULLの場合に返されます。また、キーサイズが32、48、または64バイトでない場合にも返されます。
    \return AES_SIV_AUTH_E S2Vによって導出されたSIVが入力SIVと一致しない場合（RFC 5297 2.7を参照）。
    \return Other AESまたはCMAC操作が失敗した場合に返されるその他の負のエラー値。

    \param key 使用するキーを含むバイトバッファ。
    \param keySz キーバッファの長さ（バイト単位）。
    \param assoc 追加の認証された関連データ（AD）。
    \param assocSz ADバッファの長さ（バイト単位）。
    \param nonce 1回のみ使用される数値。基盤となるアルゴリズムによってADと同じ方法で使用されます。
    \param nonceSz nonceバッファの長さ（バイト単位）。
    \param in 復号する暗号文バッファ。
    \param inSz 暗号文バッファの長さ。
    \param siv 暗号文に付随するSIV（RFC 5297 2.4を参照）。
    \param out 復号された平文を保持するバッファ。暗号文バッファと同じ長さである必要があります。

    _Example_
    \code
    byte key[] = { 32、48、または64バイトのキー };
    byte assoc[] = {0x01, 0x2, 0x3};
    byte nonce[] = {0x04, 0x5, 0x6};
    byte cipherText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte siv[AES_BLOCK_SIZE] = { 暗号文に付属していたSIV };
    byte plainText[sizeof(cipherText)];
    if (wc_AesSivDecrypt(key, sizeof(key), assoc, sizeof(assoc), nonce,
        sizeof(nonce), cipherText, sizeof(cipherText), siv, plainText) != 0) {
        // 復号に失敗
    }
    \endcode

    \sa wc_AesSivEncrypt
*/

int wc_AesSivDecrypt(const byte* key, word32 keySz, const byte* assoc,
                     word32 assocSz, const byte* nonce, word32 nonceSz,
                     const byte* in, word32 inSz, byte* siv, byte* out);







/*!
    \ingroup AES

    \brief この関数は、「EAX: A Conventional Authenticated-Encryption Mode」（https://eprint.iacr.org/2003/069）で説明されているAES EAX暗号化と認証を実行します。これは、すべての暗号化と認証操作を1つの関数呼び出しで実行する「ワンショット」APIです。

    \return 0 暗号化に成功した場合。
    \return BAD_FUNC_ARG 入力または出力バッファがNULLの場合に返されます。また、キーサイズが有効なAESキーサイズ（16、24、または32バイト）でない場合にも返されます
    \return other AESまたはCMAC操作が失敗した場合に返されるその他の負のエラー値。

    \param key 使用するキーを含むバッファ
    \param keySz キーバッファの長さ（バイト単位）
    \param[out] out 暗号文を保持するバッファ。平文バッファと同じ長さである必要があります
    \param in 暗号化する平文バッファ
    \param inSz 平文バッファの長さ
    \param nonce EAX操作に使用する暗号ナンス
    \param nonceSz nonceバッファの長さ（バイト単位）
    \param[out] authTag 認証タグを格納するバッファへのポインタ
    \param authTagSz 希望する認証タグの長さ
    \param authIn 認証する入力データを含むバッファへのポインタ
    \param authInSz 入力認証データの長さ

    _Example_
    \code
    byte key[] = { 32、48、または64バイトのキー };
    byte nonce[] = {0x04, 0x5, 0x6};
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte authIn[] = {0x01, 0x2, 0x3};

    byte cipherText[sizeof(plainText)]; // 出力暗号文
    byte authTag[length, up to AES_BLOCK_SIZE]; // 出力authTag

    if (wc_AesEaxEncrypt(key, sizeof(key),
                         cipherText, plainText, sizeof(plainText),
                         nonce, sizeof(nonce),
                         authTag, sizeof(authTag),
                         authIn, sizeof(authIn)) != 0) {
        // 暗号化に失敗
    }

    \endcode

    \sa wc_AesEaxDecryptAuth

*/
WOLFSSL_API int  wc_AesEaxEncryptAuth(const byte* key, word32 keySz, byte* out,
                                      const byte* in, word32 inSz,
                                      const byte* nonce, word32 nonceSz,
                                      /* 計算された認証タグの出力 */
                                      byte* authTag, word32 authTagSz,
                                      /* 認証する入力データ */
                                      const byte* authIn, word32 authInSz);
/*!
    \ingroup AES

    \brief この関数は、「EAX: A Conventional Authenticated-Encryption Mode」（https://eprint.iacr.org/2003/069）で説明されているAES EAX復号と認証を実行します。これは、すべての復号と認証操作を1つの関数呼び出しで実行する「ワンショット」APIです。ゼロ以外のエラーコードが返された場合、出力データは未定義です。ただし、呼び出し元は平文データの漏洩を防ぐために、無条件に出力バッファをゼロ化する必要があります。

    \return 0 復号に成功した場合
    \return BAD_FUNC_ARG 入力または出力バッファがNULLの場合に返されます。また、キーサイズが有効なAESキーサイズ（16、24、または32バイト）でない場合にも返されます
    \return AES_EAX_AUTH_E 認証タグが提供された認証コードベクトル \c authTag と一致しない場合
    \return other AESまたはCMAC操作が失敗した場合に返されるその他の負のエラー値。

    \param key 使用するキーを含むバイトバッファ
    \param keySz キーバッファの長さ（バイト単位）
    \param[out] out 平文を保持するバッファ。入力暗号文バッファと同じ長さである必要があります
    \param in 復号する暗号文バッファ
    \param inSz 暗号文バッファの長さ
    \param nonce EAX操作に使用する暗号ナンス
    \param nonceSz nonceバッファの長さ（バイト単位）
    \param authTag データの真正性をチェックするために照合する認証タグを保持するバッファ
    \param authTagSz 入力認証タグの長さ
    \param authIn 認証する入力データを含むバッファへのポインタ
    \param authInSz 入力認証データの長さ

    _Example_
    \code
    byte key[] = { 32、48、または64バイトのキー };
    byte nonce[] = {0x04, 0x5, 0x6};
    byte cipherText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte authIn[] = {0x01, 0x2, 0x3};

    byte plainText[sizeof(cipherText)]; // 出力平文
    byte authTag[length, up to AES_BLOCK_SIZE]; // 出力authTag

    if (wc_AesEaxDecrypt(key, sizeof(key),
                         cipherText, plainText, sizeof(plainText),
                         nonce, sizeof(nonce),
                         authTag, sizeof(authTag),
                         authIn, sizeof(authIn)) != 0) {
        // 暗号化に失敗
    }

    \endcode

    \sa wc_AesEaxEncryptAuth

*/
WOLFSSL_API int  wc_AesEaxDecryptAuth(const byte* key, word32 keySz, byte* out,
                                      const byte* in, word32 inSz,
                                      const byte* nonce, word32 nonceSz,
                                      /* 検証する認証タグ */
                                      const byte* authTag, word32 authTagSz,
                                      /* 認証する入力データ */
                                      const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief この関数は、認証付き暗号化または復号で使用するAesEaxオブジェクトを初期化します。この関数は、AES EAX増分APIのいずれかと使用する前に、AesEaxオブジェクトに対して呼び出す必要があります。ワンショットEAX API関数を使用する場合は呼び出す必要はありません。この関数で初期化されたすべてのAesEaxインスタンスは、インスタンスの使用が完了したらwc_AesEaxFree()の呼び出しで解放する必要があります。

    \return 0 成功した場合
    \return error code 失敗した場合のエラーコード

    \param eax AEAD操作のコンテキストを保持するAES EAX構造体
    \param key 暗号化と復号のための16、24、または32バイトの秘密鍵
    \param keySz 提供されたキーの長さ（バイト単位）
    \param nonce EAX操作に使用する暗号ナンス
    \param nonceSz nonceバッファの長さ（バイト単位）
    \param authIn （オプション）認証ストリームに追加する入力データ
    使用しない場合、この引数はNULLである必要があります
    \param authInSz 入力認証データのサイズ（バイト単位）

    _Example_
    \code
    AesEax eax;
    key[]   = { 16、24、または32バイト長のキー };
    nonce[] = { 任意の長さのnonce };
    authIn[] = { 認証ストリームに追加するデータ };
    plainText[] = {暗号化する平文データ};

    cipherText[sizeof(plainText)]; // cipherTextを保持するバッファ
    authTag[length, up to AES_BLOCK_SIZE]; // 計算された認証データを保持するバッファ

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // さらに認証データを追加したい場合は、この時点で提供できます
    // そうでない場合は、authInパラメータにNULLを使用し、authInサイズは0です
    if ((ret = wc_AesEaxEncryptUpdate(eax,
                                      cipherText, plainText, sizeof(plainText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxEncryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxInit(AesEax* eax,
                               const byte* key, word32 keySz,
                               const byte* nonce, word32 nonceSz,
                               const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief この関数は、AES EAXを使用して入力データを暗号化し、オプションで認証ストリームにさらに入力データを追加します。\c eax は、\ref wc_AesEaxInit の呼び出しで事前に初期化されている必要があります。

    \return 0 成功した場合
    \return error code 失敗した場合のエラーコード

    \param eax AEAD操作のコンテキストを保持するAES EAX構造体
    \param[out] out 暗号文を保持する出力バッファ
    \param in 暗号化する平文を保持する入力バッファ
    \param inSz 入力データバッファのサイズ（バイト単位）
    \param authIn （オプション）認証ストリームに追加する入力データ
    使用しない場合、この引数はNULLである必要があります
    \param authInSz 入力認証データのサイズ（バイト単位）

    _Example_
    \code
    AesEax eax;
    key[]   = { 16、24、または32バイト長のキー };
    nonce[] = { 任意の長さのnonce };
    authIn[] = { 認証ストリームに追加するデータ };
    plainText[] = {暗号化する平文データ};

    cipherText[sizeof(plainText)]; // cipherTextを保持するバッファ
    authTag[length, up to AES_BLOCK_SIZE]; // 計算された認証データを保持するバッファ

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // さらに認証データを追加したい場合は、この時点で提供できます
    // そうでない場合は、authInパラメータにNULLを使用し、authInSzは0です
    if ((ret = wc_AesEaxEncryptUpdate(eax,
                                      cipherText, plainText, sizeof(plainText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxEncryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxEncryptUpdate(AesEax* eax, byte* out,
                                        const byte* in, word32 inSz,
                                        const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief この関数は、AES EAXを使用して入力データを復号し、オプションで認証ストリームにさらに入力データを追加します。\c eax は、\ref wc_AesEaxInit の呼び出しで事前に初期化されている必要があります。

    \return 0 成功した場合
    \return error code 失敗した場合のエラーコード

    \param eax AEAD操作のコンテキストを保持するAES EAX構造体
    \param[out] out 復号された平文を保持する出力バッファ
    \param in 暗号文を保持する入力バッファ
    \param inSz 入力データバッファのサイズ（バイト単位）
    \param authIn （オプション）認証ストリームに追加する入力データ
    使用しない場合、この引数はNULLである必要があります
    \param authInSz 入力認証データのサイズ（バイト単位）


    _Example_
    \code
    AesEax eax;
    key[]   = { 16、24、または32バイト長のキー };
    nonce[] = { 任意の長さのnonce };
    authIn[] = { 認証ストリームに追加するデータ };
    cipherText[] = {暗号化されたデータ};

    plainText[sizeof(cipherText)]; // 復号されたデータを保持するバッファ
    // 認証タグは、暗号化AEAD操作によって別の場所で生成されます
    authTag[length, up to AES_BLOCK_SIZE] = { 認証タグ };

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // さらに認証データを追加したい場合は、この時点で提供できます
    // そうでない場合は、authInパラメータにNULLを使用し、authInSzは0です
    if ((ret = wc_AesEaxDecryptUpdate(eax,
                                      plainText, cipherText, sizeof(cipherText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxDecryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxDecryptUpdate(AesEax* eax, byte* out,
                                        const byte* in, word32 inSz,
                                        const byte* authIn, word32 authInSz);
/*!
    \ingroup AES
    \brief この関数は、認証ストリームに入力データを追加します。\c eax は、\ref wc_AesEaxInit の呼び出しで事前に初期化されている必要があります。

    \return 0 成功した場合
    \return error code 失敗した場合のエラーコード

    \param eax AEAD操作のコンテキストを保持するAES EAX構造体
    \param authIn 認証ストリームに追加する入力データ
    \param authInSz 入力認証データのサイズ（バイト単位）

    _Example_
    \code
    AesEax eax;
    key[]   = { 16、24、または32バイト長のキー };
    nonce[] = { 任意の長さのnonce };
    authIn[] = { 認証ストリームに追加するデータ };
    cipherText[] = {暗号化されたデータ};

    plainText[sizeof(cipherText)]; // 復号されたデータを保持するバッファ
    // 認証タグは、暗号化AEAD操作によって別の場所で生成されます
    authTag[length, up to AES_BLOCK_SIZE] = { 認証タグ };

    AesEax eax;

    // ここでは追加する認証データなし
    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             NULL, 0)) != 0) {
        goto cleanup;
    }

    // ここでは追加する認証データなし、後でwc_AesEaxAuthDataUpdateで追加
    if ((ret = wc_AesEaxDecryptUpdate(eax,
                                      plainText, cipherText, sizeof(cipherText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxAuthDataUpdate(eax, authIn, sizeof(authIn))) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxDecryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxAuthDataUpdate(AesEax* eax,
                                       const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief この関数は、暗号化AEAD操作を完了し、現在の認証ストリームに対して認証タグを生成します。\c eax は、\ref wc_AesEaxInit の呼び出しで事前に初期化されている必要があります。\c AesEax コンテキスト構造体の使用が完了したら、\ref wc_AesEaxFree を使用して必ず解放してください。

    \return 0 成功した場合
    \return error code 失敗した場合のエラーコード

    \param eax AEAD操作のコンテキストを保持するAES EAX構造体
    \param authTag[out] 計算された認証タグを保持するバッファ
    \param authTagSz \c authTag のサイズ（バイト単位）

    _Example_
    \code
    AesEax eax;
    key[]   = { 16、24、または32バイト長のキー };
    nonce[] = { 任意の長さのnonce };
    authIn[] = { 認証ストリームに追加するデータ };
    plainText[] = {暗号化する平文データ};
    cipherText[sizeof(plainText)]; // cipherTextを保持するバッファ
    authTag[length, up to AES_BLOCK_SIZE]; // 計算された認証データを保持するバッファ

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // さらに認証データを追加したい場合は、この時点で提供できます
    // そうでない場合は、authInパラメータにNULLを使用し、authInSzは0です
    if ((ret = wc_AesEaxEncryptUpdate(eax,
                                      cipherText, plainText, sizeof(plainText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxEncryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int wc_AesEaxEncryptFinal(AesEax* eax,
                                      byte* authTag, word32 authTagSz);

/*!
    \ingroup AES
    \brief この関数は、復号AEAD操作を完了し、認証タグの計算を完了して、ユーザが提供したタグに対してその有効性をチェックします。\c eax は、\ref wc_AesEaxInit の呼び出しで事前に初期化されている必要があります。\c AesEax コンテキスト構造体の使用が完了したら、\ref wc_AesEaxFree を使用して必ず解放してください。

    \return 0 データが正常に認証された場合
    \return AES_EAX_AUTH_E 認証タグが提供された認証コードベクトル \c authIn と一致しない場合
    \return other error code 失敗した場合のその他のエラーコード

    \param eax AEAD操作のコンテキストを保持するAES EAX構造体
    \param authIn 計算された認証タグと照合するための入力認証タグ
    \param authInSz \c authIn のサイズ（バイト単位）

    _Example_
    \code
    AesEax eax;
    key[]   = { 16、24、または32バイト長のキー };
    nonce[] = { 任意の長さのnonce };
    authIn[] = { 認証ストリームに追加するデータ };
    cipherText[] = {暗号化されたデータ};

    plainText[sizeof(cipherText)]; // 復号されたデータを保持するバッファ
    // 認証タグは、暗号化AEAD操作によって別の場所で生成されます
    authTag[length, up to AES_BLOCK_SIZE] = { 認証タグ };

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // さらに認証データを追加したい場合は、この時点で提供できます
    // そうでない場合は、authInパラメータにNULLを使用し、authInSzは0です
    if ((ret = wc_AesEaxDecryptUpdate(eax,
                                      plainText, cipherText, sizeof(cipherText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxDecryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int wc_AesEaxDecryptFinal(AesEax* eax,
                                      const byte* authIn, word32 authInSz);
/*!
    \ingroup AES

    \brief この関数は、AesEaxラッパー構造体内のAesインスタンスによって使用されるリソース、特にキーを解放します。wc_AesEaxInitで初期化された後、すべての必要なEAX操作が完了した時点でAesEax構造体に対して呼び出す必要があります。

    \return 0 成功

    \param eax 解放するAES EAXインスタンス

    _Example_
    \code
    AesEax eax;

    if(wc_AesEaxInit(eax, key, keySz, nonce, nonceSz, authIn, authInSz) != 0) {
        // エラーを処理し、その後解放
        wc_AesEaxFree(&eax);
    }
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
*/
WOLFSSL_API int wc_AesEaxFree(AesEax* eax);

/*!
    \ingroup AES
    \brief この関数は、CTSモードを使用してAES暗号化を実行します。これは、すべての操作を1回の呼び出しで処理するワンショットAPIです。

    \return 0 暗号化に成功した場合。
    \return BAD_FUNC_ARG 入力引数が無効な場合。
    \return other negative error codes 暗号化失敗のためのその他の負のエラーコード。

    \param key 暗号化に使用されるAESキーへのポインタ。
    \param keySz AESキーのサイズ（バイト単位）（16、24、または32バイト）。
    \param[out] out 暗号化された暗号文を保持するバッファ。少なくとも入力と同じサイズである必要があります。
    \param in 暗号化する平文入力データへのポインタ。
    \param inSz 平文入力データのサイズ（バイト単位）。
    \param iv 暗号化に使用される初期化ベクトル（IV）へのポインタ。16バイトである必要があります。

    _Example_
    \code
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte ciphertext[sizeof(plaintext)];

        int ret = wc_AesCtsEncrypt(key, sizeof(key), ciphertext, plaintext,
            sizeof(plaintext), iv);
        if (ret != 0) {
        // 暗号化エラーを処理
    }
    \endcode

    \sa wc_AesCtsDecrypt
*/
int wc_AesCtsEncrypt(const byte* key, word32 keySz, byte* out,
                     const byte* in, word32 inSz,
                     const byte* iv);

/*!
    \ingroup AES
    \brief この関数は、CTSモードを使用してAES暗号化を実行します。これは、すべての操作を1回の呼び出しで処理するワンショットAPIです。

    \return 0 暗号化に成功した場合。
    \return BAD_FUNC_ARG 入力引数が無効な場合。
    \return other negative error codes 暗号化失敗のためのその他の負のエラーコード。

    \param key 暗号化に使用されるAESキーへのポインタ。
    \param keySz AESキーのサイズ（バイト単位）（16、24、または32バイト）。
    \param[out] out 暗号化された暗号文を保持するバッファ。少なくとも入力平文と同じサイズである必要があります。
    \param in 暗号化する平文入力データへのポインタ。
    \param inSz 平文入力データのサイズ（バイト単位）。
    \param iv 暗号化に使用される初期化ベクトル（IV）へのポインタ。16バイトである必要があります。
    _Example_
    \code
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte ciphertext[sizeof(plaintext)];
        int ret = wc_AesCtsEncrypt(key, sizeof(key), ciphertext, plaintext,
                                   sizeof(plaintext), iv);
        if (ret != 0) {
            // 暗号化エラーを処理
        }
    \endcode
    \sa wc_AesCtsDecrypt
*/
int wc_AesCtsEncrypt(const byte* key, word32 keySz, byte* out,
                     const byte* in, word32 inSz,
                     const byte* iv);

/*!
    \ingroup AES
    \brief この関数は、CTSモードを使用してAES復号を実行します。これは、すべての操作を1回の呼び出しで処理するワンショットAPIです。
    \return 0 復号に成功した場合。
    \return BAD_FUNC_ARG 入力引数が無効な場合。
    \return other negative error codes 復号失敗のためのその他の負のエラーコード。
    \param key 復号に使用されるAESキーへのポインタ。
    \param keySz AESキーのサイズ（バイト単位）（16、24、または32バイト）。
    \param[out] out 復号された平文を保持するバッファ。少なくとも入力暗号文と同じサイズである必要があります。
    \param in 復号する暗号文入力データへのポインタ。
    \param inSz 暗号文入力データのサイズ（バイト単位）。
    \param iv 復号に使用される初期化ベクトル（IV）へのポインタ。16バイトである必要があります。
    _Example_
    \code
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte ciphertext[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte plaintext[sizeof(ciphertext)];
        int ret = wc_AesCtsDecrypt(key, sizeof(key), plaintext, ciphertext,
                                   sizeof(ciphertext), iv);
        if (ret != 0) {
            // 復号エラーを処理
        }
    \endcode
    \sa wc_AesCtsEncrypt
*/
int wc_AesCtsDecrypt(const byte* key, word32 keySz, byte* out,
                     const byte* in, word32 inSz,
                     const byte* iv);

/*!
    \ingroup AES
    \brief この関数は、AES CTS暗号化の更新ステップを実行します。平文のチャンクを処理し、中間データを保存します。
    \return 0 処理に成功した場合。
    \return BAD_FUNC_ARG 入力引数が無効な場合。
    \param aes 操作のコンテキストを保持するAes構造体へのポインタ。
    \param[out] out 暗号化された暗号文を保持するバッファ。この更新ステップからの出力を保存するのに十分な大きさである必要があります。
    \param[out] outSz \c out バッファに書き込まれた出力データのサイズ（バイト単位）。入力時には、\c out バッファに書き込むことができる最大バイト数を含める必要があります。
    \param in 暗号化する平文入力データへのポインタ。
    \param inSz 平文入力データのサイズ（バイト単位）。
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { ... };
        byte ciphertext[sizeof(plaintext)];
        word32 outSz = sizeof(ciphertext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION);
        int ret = wc_AesCtsEncryptUpdate(&aes, ciphertext, &outSz, plaintext, sizeof(plaintext));
        if (ret != 0) {
            // エラーを処理
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsDecryptUpdate
*/
int wc_AesCtsEncryptUpdate(Aes* aes, byte* out, word32* outSz,
                           const byte* in, word32 inSz);

/*!
    \ingroup AES
    \brief この関数は、AES CTS暗号化操作を完了します。残りの平文を処理し、暗号化を完了します。
    \return 0 暗号化の完了に成功した場合。
    \return BAD_FUNC_ARG 入力引数が無効な場合。
    \param aes 操作のコンテキストを保持するAes構造体へのポインタ。
    \param[out] out 最終的な暗号化された暗号文を保持するバッファ。この最終ステップから残りの暗号文を保存するのに十分な大きさである必要があります。
    \param[out] outSz \c out バッファに書き込まれた出力データのサイズ（バイト単位）。入力時には、\c out バッファに書き込むことができる最大バイト数を含める必要があります。
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { ... };
        byte ciphertext[sizeof(plaintext)];
        word32 outSz = sizeof(ciphertext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION);
        // wc_AesCtsEncryptUpdateを使用して必要な更新ステップを実行
        int ret = wc_AesCtsEncryptFinal(&aes, ciphertext, &outSz);
        if (ret != 0) {
            // エラーを処理
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsDecryptFinal
*/
int wc_AesCtsEncryptFinal(Aes* aes, byte* out, word32* outSz);

/*!
    \ingroup AES
    \brief この関数は、AES CTS復号の更新ステップを実行します。暗号文のチャンクを処理し、中間データを保存します。
    \return 0 処理に成功した場合。
    \return BAD_FUNC_ARG 入力引数が無効な場合。
    \param aes 操作のコンテキストを保持するAes構造体へのポインタ。
    \param[out] out 復号された平文を保持するバッファ。この更新ステップからの出力を保存するのに十分な大きさである必要があります。
    \param[out] outSz \c out バッファに書き込まれた出力データのサイズ（バイト単位）。入力時には、\c out バッファに書き込むことができる最大バイト数を含める必要があります。
    \param in 復号する暗号文入力データへのポインタ。
    \param inSz 暗号文入力データのサイズ（バイト単位）。
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte ciphertext[] = { ... };
        byte plaintext[sizeof(ciphertext)];
        word32 outSz = sizeof(plaintext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_DECRYPTION);
        int ret = wc_AesCtsDecryptUpdate(&aes, plaintext, &outSz, ciphertext, sizeof(ciphertext));
        if (ret != 0) {
            // エラーを処理
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsEncryptUpdate
*/
int wc_AesCtsDecryptUpdate(Aes* aes, byte* out, word32* outSz,
                           const byte* in, word32 inSz);

/*!
    \ingroup AES
    \brief この関数は、AES CTS復号操作を完了します。残りの暗号文を処理し、復号を完了します。
    \return 0 復号の完了に成功した場合。
    \return BAD_FUNC_ARG 入力引数が無効な場合。
    \param aes 操作のコンテキストを保持するAes構造体へのポインタ。
    \param[out] out 最終的な復号された平文を保持するバッファ。この最終ステップから残りの平文を保存するのに十分な大きさである必要があります。
    \param[out] outSz \c out バッファに書き込まれた出力データのサイズ（バイト単位）。入力時には、\c out バッファに書き込むことができる最大バイト数を含める必要があります。
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte ciphertext[] = { ... };
        byte plaintext[sizeof(ciphertext)];
        word32 outSz = sizeof(plaintext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_DECRYPTION);
        // wc_AesCtsDecryptUpdateを使用して必要な更新ステップを実行
        int ret = wc_AesCtsDecryptFinal(&aes, plaintext, &outSz);
        if (ret != 0) {
            // エラーを処理
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsEncryptFinal
*/
int wc_AesCtsDecryptFinal(Aes* aes, byte* out, word32* outSz);
