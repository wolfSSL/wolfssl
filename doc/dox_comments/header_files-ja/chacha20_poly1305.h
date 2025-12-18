/*!
    \ingroup ChaCha20Poly1305

    \brief この関数は、入力メッセージinPlaintextをChaCha20ストリーム暗号を使用して暗号化し、出力バッファoutCiphertextに格納します。また、Poly-1305認証(暗号文に対して)を実行し、生成された認証タグを出力バッファoutAuthTagに格納します。

    \return 0 メッセージの暗号化に成功した場合に返されます
    \return BAD_FUNC_ARG 暗号化プロセス中にエラーが発生した場合に返されます

    \param inKey 暗号化に使用する32バイトのキーを含むバッファへのポインタ
    \param inIv 暗号化に使用する12バイトのivを含むバッファへのポインタ
    \param inAAD 任意の長さの追加認証データ(AAD)を含むバッファへのポインタ
    \param inAADLen 入力AADの長さ
    \param inPlaintext 暗号化する平文を含むバッファへのポインタ
    \param inPlaintextLen 暗号化する平文の長さ
    \param outCiphertext 暗号文を格納するバッファへのポインタ
    \param outAuthTag 認証タグを格納する16バイト幅のバッファへのポインタ

    _Example_
    \code
    byte key[] = { // 32バイトのキーを初期化 };
    byte iv[]  = { // 12バイトのキーを初期化 };
    byte inAAD[] = { // AADを初期化 };

    byte plain[] = { // 暗号化するメッセージを初期化 };
    byte cipher[sizeof(plain)];
    byte authTag[16];

    int ret = wc_ChaCha20Poly1305_Encrypt(key, iv, inAAD, sizeof(inAAD),
    plain, sizeof(plain), cipher, authTag);

    if(ret != 0) {
    	// 暗号化実行エラー
    }
    \endcode

    \sa wc_ChaCha20Poly1305_Decrypt
    \sa wc_ChaCha_*
    \sa wc_Poly1305*
*/

int wc_ChaCha20Poly1305_Encrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, word32 inAADLen,
                const byte* inPlaintext, word32 inPlaintextLen,
                byte* outCiphertext,
                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);

/*!
    \ingroup ChaCha20Poly1305

    \brief この関数は、入力暗号文inCiphertextをChaCha20ストリーム暗号を使用して復号し、出力バッファoutPlaintextに格納します。また、Poly-1305認証を実行し、指定されたinAuthTagとinAAD(任意の長さの追加認証データ)で生成された認証を比較します。ゼロ以外のエラーコードが返された場合、出力データoutPlaintextは未定義です。ただし、呼び出し元は平文データの漏洩を防ぐために、無条件に出力バッファをゼロ化する必要があります。

    \return 0 メッセージの復号と認証に成功した場合に返されます
    \return BAD_FUNC_ARG 関数の引数が期待される内容と一致しない場合に返されます
    \return MAC_CMP_FAILED_E 生成された認証タグが提供されたinAuthTagと一致しない場合に返されます
    \return MEMORY_E 内部バッファの割り当てに失敗した場合に返されます
    \return CHACHA_POLY_OVERFLOW 入力が破損している場合に返される可能性があります

    \param inKey 復号に使用する32バイトのキーを含むバッファへのポインタ
    \param inIv 復号に使用する12バイトのivを含むバッファへのポインタ
    \param inAAD 任意の長さの追加認証データ(AAD)を含むバッファへのポインタ
    \param inAADLen 入力AADの長さ
    \param inCiphertext 復号する暗号文を含むバッファへのポインタ
    \param outCiphertextLen 復号する暗号文の長さ
    \param inAuthTag 認証用の16バイトのダイジェストを含むバッファへのポインタ
    \param outPlaintext 平文を格納するバッファへのポインタ

    _Example_
    \code
    byte key[]   = { // 32バイトのキーを初期化 };
    byte iv[]    = { // 12バイトのキーを初期化 };
    byte inAAD[] = { // AADを初期化 };

    byte cipher[]    = { // 受信した暗号文で初期化 };
    byte authTag[16] = { // 受信した認証タグで初期化 };

    byte plain[sizeof(cipher)];

    int ret = wc_ChaCha20Poly1305_Decrypt(key, iv, inAAD, sizeof(inAAD),
    cipher, sizeof(cipher), authTag, plain);

    if(ret == MAC_CMP_FAILED_E) {
    	// 認証中のエラー
    } else if( ret != 0) {
    	// 関数引数のエラー
    }
    \endcode

    \sa wc_ChaCha20Poly1305_Encrypt
    \sa wc_ChaCha_*
    \sa wc_Poly1305*
*/

int wc_ChaCha20Poly1305_Decrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, word32 inAADLen,
                const byte* inCiphertext, word32 inCiphertextLen,
                const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                byte* outPlaintext);
