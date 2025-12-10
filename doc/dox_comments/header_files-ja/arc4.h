/*!
    \ingroup ARC4
    \brief この関数は、バッファinから入力メッセージを暗号化し、暗号文を出力バッファoutに格納するか、またはバッファinから暗号文を復号し、平文を出力バッファoutに格納します。ARC4暗号化を使用します。この関数は暗号化と復号の両方に使用されます。このメソッドを呼び出す前に、wc_Arc4SetKeyを使用してARC4構造体を初期化する必要があります。

    \return none

    \param arc4 メッセージを処理するために使用されるARC4構造体へのポインタ
    \param out 処理されたメッセージを格納する出力バッファへのポインタ
    \param in 処理するメッセージを含む入力バッファへのポインタ
    \param length 処理するメッセージの長さ

    _Example_
    \code
    Arc4 enc;
    byte key[] = { 暗号化に使用するキー };
    wc_Arc4SetKey(&enc, key, sizeof(key));

    byte plain[] = { エンコードする平文 };
    byte cipher[sizeof(plain)];
    byte decrypted[sizeof(plain)];
    // plainをcipherに暗号化
    wc_Arc4Process(&enc, cipher, plain, sizeof(plain));
    // cipherを復号
    wc_Arc4Process(&enc, decrypted, cipher, sizeof(cipher));
    \endcode

    \sa wc_Arc4SetKey
*/
int wc_Arc4Process(Arc4* arc4, byte* out, const byte* in, word32 length);

/*!
    \ingroup ARC4

    \brief この関数は、ARC4オブジェクトのキーを設定し、暗号として使用するために初期化します。wc_Arc4Processで暗号化に使用する前に呼び出す必要があります。

    \return none

    \param arc4 暗号化に使用されるarc4構造体へのポインタ
    \param key arc4構造体を初期化するために使用するキー
    \param length arc4構造体を初期化するために使用するキーの長さ

    _Example_
    \code
    Arc4 enc;
    byte key[] = { 暗号化に使用するキーで初期化 };
    wc_Arc4SetKey(&enc, key, sizeof(key));
    \endcode

    \sa wc_Arc4Process
*/
int wc_Arc4SetKey(Arc4* arc4, const byte* key, word32 length);
