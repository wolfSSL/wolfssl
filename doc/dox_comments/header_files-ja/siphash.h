/*!
    \ingroup SipHash

    \brief この関数は、MACサイズに対するキーを使用してSipHashを初期化します。

    \return 0 初期化に成功した場合に返されます
    \return BAD_FUNC_ARG sipHashまたはkeyがNULLの場合に返されます
    \return BAD_FUNC_ARG outSzが8でも16でもない場合に返されます

    \param siphash MACに使用するSipHash構造体へのポインタ
    \param key 16バイト配列へのポインタ
    \param outSz MACとして出力するバイト数

    _Example_
    \code
    SipHash siphash[1];
    unsigned char key[16] = { ... };
    byte macSz = 8; // 8または16

    if ((ret = wc_InitSipHash(siphash, key, macSz)) != 0) {
        WOLFSSL_MSG("wc_InitSipHash failed");
    }
    else if ((ret = wc_SipHashUpdate(siphash, data, len)) != 0) {
        WOLFSSL_MSG("wc_SipHashUpdate failed");
    }
    else if ((ret = wc_SipHashFinal(siphash, mac, macSz)) != 0) {
        WOLFSSL_MSG("wc_SipHashFinal failed");
    }
    \endcode

    \sa wc_SipHash
    \sa wc_SipHashUpdate
    \sa wc_SipHashFinal
*/
int wc_InitSipHash(SipHash* siphash, const unsigned char* key,
    unsigned char outSz);

/*!
    \ingroup SipHash

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 MACへのデータ追加に成功した場合に返されます
    \return BAD_FUNC_ARG siphashがNULLの場合に返されます
    \return BAD_FUNC_ARG inがNULLでinSzがゼロでない場合に返されます

    \param siphash MACに使用するSipHash構造体へのポインタ
    \param in MACするデータ
    \param inSz MACするデータのサイズ

    _Example_
    \code
    SipHash siphash[1];
    byte data[] = { MACするデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSipHash(siphash, key, macSz)) != 0) {
        WOLFSSL_MSG("wc_InitSipHash failed");
    }
    else if ((ret = wc_SipHashUpdate(siphash, data, len)) != 0) {
        WOLFSSL_MSG("wc_SipHashUpdate failed");
    }
    else if ((ret = wc_SipHashFinal(siphash, mac, macSz)) != 0) {
        WOLFSSL_MSG("wc_SipHashFinal failed");
    }
    \endcode

    \sa wc_SipHash
    \sa wc_InitSipHash
    \sa wc_SipHashFinal
*/
int wc_SipHashUpdate(SipHash* siphash, const unsigned char* in,
    word32 inSz);

/*!
    \ingroup SipHash

    \brief データのMAC処理を完了します。結果はoutに格納されます。

    \return 0 完了に成功した場合に返されます。
    \return BAD_FUNC_ARG siphashまたはoutがNULLの場合に返されます
    \return BAD_FUNC_ARG outSzが初期化された値と同じでない場合に返されます

    \param siphash MACに使用するSipHash構造体へのポインタ
    \param out MAC値を保持するバイト配列
    \param outSz MACとして出力するバイト数

    _Example_
    \code
    SipHash siphash[1];
    byte mac[8] = { ... }; // 8または16バイト
    byte macSz = sizeof(mac);

    if ((ret = wc_InitSipHash(siphash, key, macSz)) != 0) {
        WOLFSSL_MSG("wc_InitSipHash failed");
    }
    else if ((ret = wc_SipHashUpdate(siphash, data, len)) != 0) {
        WOLFSSL_MSG("wc_SipHashUpdate failed");
    }
    else if ((ret = wc_SipHashFinal(siphash, mac, macSz)) != 0) {
        WOLFSSL_MSG("wc_SipHashFinal failed");
    }
    \endcode

    \sa wc_SipHash
    \sa wc_InitSipHash
    \sa wc_SipHashUpdate
*/
int wc_SipHashFinal(SipHash* siphash, unsigned char* out,
    unsigned char outSz);

/*!
    \ingroup SipHash

    \brief この関数は、キーに基づいてMACを計算するために、SipHashを使用してデータをワンショットで処理します。

    \return 0 MACに成功した場合に返されます
    \return BAD_FUNC_ARG keyまたはoutがNULLの場合に返されます
    \return BAD_FUNC_ARG inがNULLでinSzがゼロでない場合に返されます
    \return BAD_FUNC_ARG outSzが8でも16でもない場合に返されます

    \param key 16バイト配列へのポインタ
    \param in MACするデータ
    \param inSz MACするデータのサイズ
    \param out MAC値を保持するバイト配列
    \param outSz MACとして出力するバイト数

    _Example_
    \code
    unsigned char key[16] = { ... };
    byte data[] = { MACするデータ };
    word32 len = sizeof(data);
    byte mac[8] = { ... }; // 8または16バイト
    byte macSz = sizeof(mac);

    if ((ret = wc_SipHash(key, data, len, mac, macSz)) != 0) {
        WOLFSSL_MSG("wc_SipHash failed");
    }
    \endcode

    \sa wc_InitSipHash
    \sa wc_SipHashUpdate
    \sa wc_SipHashFinal
*/
int wc_SipHash(const unsigned char* key, const unsigned char* in,
    word32 inSz, unsigned char* out, unsigned char outSz);