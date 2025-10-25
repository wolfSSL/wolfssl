/*!
    \ingroup ASCON
    \brief この関数は、ハッシュ化のためにASCONコンテキストを初期化します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストポインタがNULLの場合。

    \param a 初期化するASCONコンテキストへのポインタ。

    _Example_
    \code
    wc_AsconHash256 a;
    byte data[] = {0x01, 0x02, 0x03};
    byte hash[ASCON_HASH256_SZ];

    if (wc_AsconHash256_Init(&a) != 0)
        // エラーを処理
    if (wc_AsconHash256_Update(&ctx, data, sizeof(data)) != 0)
        // エラーを処理
    if (wc_AsconHash256_Final(&ctx, hash, sizeof(hash)) != 0)
        // エラーを処理
    // hashに最終ハッシュが含まれます
    \endcode

    \sa wc_AsconHash256_Update
    \sa wc_AsconHash256_Final
    */
int wc_AsconHash256_Init(wc_AsconHash256* a);

/*!
    \ingroup ASCON
    \brief この関数は、入力データでASCONハッシュを更新します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは入力ポインタがNULLの場合。

    \param ctx ASCONコンテキストへのポインタ。
    \param in 入力データへのポインタ。
    \param inSz 入力データのサイズ。

    _Example_
    \code
    wc_AsconHash256 a;
    byte data[] = {0x01, 0x02, 0x03};
    byte hash[ASCON_HASH256_SZ];

    if (wc_AsconHash256_Init(&a) != 0)
        // エラーを処理
    if (wc_AsconHash256_Update(&ctx, data, sizeof(data)) != 0)
        // エラーを処理
    if (wc_AsconHash256_Final(&ctx, hash, sizeof(hash)) != 0)
        // エラーを処理
    // hashに最終ハッシュが含まれます
    \endcode

    \sa wc_AsconHash256_Init
    \sa wc_AsconHash256_Final
    */
int wc_AsconHash256_Update(wc_AsconHash256* a, const byte* data, word32 dataSz);

/*!
    \ingroup ASCON
    \brief この関数は、ASCONハッシュを完了し、出力を生成します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは出力ポインタがNULLの場合。

    \param ctx ASCONコンテキストへのポインタ。
    \param out 出力バッファへのポインタ。
    \param outSz 出力バッファのサイズ、少なくともASCON_HASH256_SZである必要があります。

    _Example_
    \code
    wc_AsconHash256 a;
    byte data[] = {0x01, 0x02, 0x03};
    byte hash[ASCON_HASH256_SZ];

    if (wc_AsconHash256_Init(&a) != 0)
        // エラーを処理
    if (wc_AsconHash256_Update(&ctx, data, sizeof(data)) != 0)
        // エラーを処理
    if (wc_AsconHash256_Final(&ctx, hash, sizeof(hash)) != 0)
        // エラーを処理
    // hashに最終ハッシュが含まれます
    \endcode

    \sa wc_AsconHash256_Init
    \sa wc_AsconHash256_Update
    */
int wc_AsconHash256_Final(wc_AsconHash256* a, byte* hash);

/*!
    \ingroup ASCON
    \brief この関数は、新しいAscon AEADコンテキストを割り当てて初期化します。

    \return pointer 新しく割り当てられたAscon AEADコンテキストへのポインタ
    \return NULL 失敗時。

    _Example_
    \code
    wc_AsconAEAD128* a = wc_AsconAEAD128_New();
    if (a == NULL) {
        // 割り当てエラーを処理
    }
    wc_AsconAEAD128_Free(a);
    \endcode

    \sa wc_AsconAEAD128_Free
*/
wc_AsconAEAD128* wc_AsconAEAD128_New(void);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADコンテキストに関連付けられたリソースを解放します。

    \param a 解放するAscon AEADコンテキストへのポインタ。

    _Example_
    \code
    wc_AsconAEAD128* a = wc_AsconAEAD128_New();
    if (a == NULL) {
        // 割り当てエラーを処理
    }
    // コンテキストを使用
    wc_AsconAEAD128_Free(a);
    \endcode

    \sa wc_AsconAEAD128_New
*/
void wc_AsconAEAD128_Free(wc_AsconAEAD128 *a);


/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADコンテキストを初期化します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは出力ポインタがNULLの場合。

    \param a 初期化するAscon AEADコンテキストへのポインタ。

    _Example_
    \code
    AsconAead a;

    if (wc_AsconAEAD128_Init(&a) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAeadEncrypt
    \sa wc_AsconAeadDecrypt
    */
int wc_AsconAEAD128_Init(wc_AsconAEAD128* a);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADコンテキストを非初期化します。コンテキストは解放しません。

    \param a 非初期化するAscon AEADコンテキストへのポインタ。

    _Example_
    \code
    AsconAead a;

    if (wc_AsconAEAD128_Init(&a) != 0)
        // エラーを処理
    wc_AsconAEAD128_Clear(&a);
    \endcode

    \sa wc_AsconAeadEncrypt
    \sa wc_AsconAeadDecrypt
    */
void wc_AsconAEAD128_Clear(wc_AsconAEAD128 *a);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADコンテキストの鍵を設定します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは鍵ポインタがNULLの場合。
    \return BAD_STATE_E 鍵が既に設定されている場合。

    \param a 初期化されたAscon AEADコンテキストへのポインタ。
    \param key ASCON_AEAD128_KEY_SZの長さの鍵バッファへのポインタ。

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };

    if (wc_AsconAEAD128_Init(&a) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
*/
int wc_AsconAEAD128_SetKey(wc_AsconAEAD128* a, const byte* key);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADコンテキストのnonceを設定します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたはnonceポインタがNULLの場合。
    \return BAD_STATE_E nonceが既に設定されている場合。

    \param a 初期化されたAscon AEADコンテキストへのポインタ。
    \param nonce ASCON_AEAD128_NONCE_SZの長さのnonceバッファへのポインタ。

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };

    if (wc_AsconAEAD128_Init(&a) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetAD
*/
int wc_AsconAEAD128_SetNonce(wc_AsconAEAD128* a, const byte* nonce);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADコンテキストの関連データを設定します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは関連データポインタがNULLの場合。
    \return BAD_STATE_E 鍵またはnonceが設定されていない場合。

    \param a 初期化されたAscon AEADコンテキストへのポインタ。
    \param ad 関連データバッファへのポインタ。
    \param adSz 関連データバッファのサイズ。

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte ad[] = { ... };

    if (wc_AsconAEAD128_Init(&a) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
*/
int wc_AsconAEAD128_SetAD(wc_AsconAEAD128* a, const byte* ad, word32 adSz);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADを使用して平文メッセージを暗号化します。出力はoutバッファに格納されます。出力の長さは入力の長さと等しくなります。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは出力ポインタがNULLの場合、または入力サイズが0より大きいのに入力がNULLの場合。
    \return BAD_STATE_E 鍵、nonce、または追加データが設定されていない場合、またはコンテキストが以前に復号に使用された場合。

    \param a 初期化されたAscon AEADコンテキストへのポインタ。
    \param out 暗号文を格納する出力バッファへのポインタ。
    \param in 平文メッセージを含む入力バッファへのポインタ。
    \param inSz 入力バッファの長さ。

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_EncryptUpdate(&a, ciphertext, plaintext,
                                      sizeof(plaintext)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_EncryptFinal(&a, tag) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAeadInit
    \sa wc_AsconAEAD128_Clear
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_EncryptFinal
    \sa wc_AsconAEAD128_DecryptUpdate
    \sa wc_AsconAEAD128_DecryptFinal
    */
int wc_AsconAEAD128_EncryptUpdate(wc_AsconAEAD128* a, byte* out, const byte* in,
                                  word32 inSz);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADを使用した暗号化プロセスを完了し、認証タグを生成します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは出力ポインタがNULLの場合、または入力サイズが0より大きいのに入力がNULLの場合。
    \return BAD_STATE_E 鍵、nonce、または追加データが設定されていない場合、またはコンテキストが以前に復号に使用された場合。

    \param a 初期化されたAscon AEADコンテキストへのポインタ。
    \param tag 認証タグを格納する出力バッファへのポインタ。

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_EncryptUpdate(&a, ciphertext, plaintext,
                                      sizeof(plaintext)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_EncryptFinal(&a, tag) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_EncryptUpdate
    \sa wc_AsconAEAD128_DecryptUpdate
    \sa wc_AsconAEAD128_DecryptFinal
    */
int wc_AsconAEAD128_EncryptFinal(wc_AsconAEAD128* a, byte* tag);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADを使用した復号プロセスを更新します。出力はoutバッファに格納されます。出力の長さは入力の長さと等しくなります。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたは出力ポインタがNULLの場合、または入力サイズが0より大きいのに入力がNULLの場合。
    \return BAD_STATE_E 鍵、nonce、または追加データが設定されていない場合、またはコンテキストが以前に暗号化に使用された場合。

    \param a 初期化されたAscon AEADコンテキストへのポインタ。
    \param out 平文を格納する出力バッファへのポインタ。
    \param in 暗号文メッセージを含む入力バッファへのポインタ。
    \param inSz 入力バッファの長さ。

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_DecryptUpdate(&a, plaintext, ciphertext,
                                      sizeof(ciphertext)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_DecryptFinal(&a, tag) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_EncryptUpdate
    \sa wc_AsconAEAD128_EncryptFinal
    \sa wc_AsconAEAD128_DecryptFinal
    */
int wc_AsconAEAD128_DecryptUpdate(wc_AsconAEAD128* a, byte* out, const byte* in,
                                  word32 inSz);

/*!
    \ingroup ASCON
    \brief この関数は、Ascon AEADを使用した復号プロセスを完了し、認証タグを検証します。

    \return 0 成功時。
    \return BAD_FUNC_ARG コンテキストまたはタグポインタがNULLの場合。
    \return BAD_STATE_E 鍵、nonce、または追加データが設定されていない場合、またはコンテキストが以前に暗号化に使用された場合。
    \return ASCON_AUTH_E 認証タグが一致しない場合。

    \param a 初期化されたAscon AEADコンテキストへのポインタ。
    \param tag 検証する認証タグを含むバッファへのポインタ

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_DecryptUpdate(&a, plaintext, ciphertext,
                                      sizeof(ciphertext)) != 0)
        // エラーを処理
    if (wc_AsconAEAD128_DecryptFinal(&a, tag) != 0)
        // エラーを処理
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_DecryptUpdate
    \sa wc_AsconAEAD128_EncryptUpdate
    \sa wc_AsconAEAD128_EncryptFinal
    */
int wc_AsconAEAD128_DecryptFinal(wc_AsconAEAD128* a, const byte* tag);