/*!
    \ingroup SHA

    \brief この関数はSHA3-224を初期化します。これはwc_Sha3_224Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha3 暗号化に使用するsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
        wc_Sha3_224_Update(sha3, data, len);
        wc_Sha3_224_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Update
    \sa wc_Sha3_224_Final
*/
int wc_InitSha3_224(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief 長さlenのバイト配列を継続的にハッシュ化するために呼び出すことができます。

    \return 0 ダイジェストへのデータの追加に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
        wc_Sha3_224_Update(sha3, data, len);
        wc_Sha3_224_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Final
    \sa wc_InitSha3_224
*/
int wc_Sha3_224_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。sha3構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
       wc_Sha3_224_Update(sha3, data, len);
       wc_Sha3_224_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_GetHash
    \sa wc_InitSha3_224
*/
int wc_Sha3_224_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief wc_Sha3構造体をリセットします。注：これはWOLFSSL_TI_HASHが定義されている場合のみサポートされます。

    \return none 戻り値なし。

    \param sha3 解放されるsha3構造体へのポインタ。

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_224(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
        wc_Sha3_224_Update(&sha3, data, len);
        wc_Sha3_224_Final(&sha3, hash);
        wc_Sha3_224_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_224
    \sa wc_Sha3_224_Update
    \sa wc_Sha3_224_Final
*/
void wc_Sha3_224_Free(wc_Sha3*);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。sha3構造体の状態をリセットしません。

    \return 0 ハッシュのコピーに成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
       wc_Sha3_224_Update(sha3, data, len);
       wc_Sha3_224_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Final
    \sa wc_InitSha3_224
    \sa wc_Sha3_224_Copy
*/
int wc_Sha3_224_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief ハッシュの状態をコピーします。

    \return 0 コピーに成功した場合に返されます。

    \param sha3 コピーするsha3構造体へのポインタ
    \param dst  コピー先のsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
       wc_Sha3_224_Update(sha3, data, len);
       wc_Sha3_224_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Final
    \sa wc_InitSha3_224
    \sa wc_Sha3_224_GetHash
*/
int wc_Sha3_224_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief この関数はSHA3-256を初期化します。これはwc_Sha3_256Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha3 暗号化に使用するsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
        wc_Sha3_256_Update(sha3, data, len);
        wc_Sha3_256_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Update
    \sa wc_Sha3_256_Final
*/
int wc_InitSha3_256(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief 長さlenのバイト配列を継続的にハッシュ化するために呼び出すことができます。

    \return 0 ダイジェストへのデータの追加に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
        wc_Sha3_256_Update(sha3, data, len);
        wc_Sha3_256_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Final
    \sa wc_InitSha3_256
*/
int wc_Sha3_256_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。sha3構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
       wc_Sha3_256_Update(sha3, data, len);
       wc_Sha3_256_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_GetHash
    \sa wc_InitSha3_256
*/
int wc_Sha3_256_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief wc_Sha3構造体をリセットします。注：これはWOLFSSL_TI_HASHが定義されている場合のみサポートされます。

    \return none 戻り値なし。

    \param sha3 解放されるsha3構造体へのポインタ。

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_256(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
        wc_Sha3_256_Update(&sha3, data, len);
        wc_Sha3_256_Final(&sha3, hash);
        wc_Sha3_256_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_256
    \sa wc_Sha3_256_Update
    \sa wc_Sha3_256_Final
*/
void wc_Sha3_256_Free(wc_Sha3*);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。sha3構造体の状態をリセットしません。

    \return 0 ハッシュのコピーに成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
       wc_Sha3_256_Update(sha3, data, len);
       wc_Sha3_256_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Final
    \sa wc_InitSha3_256
    \sa wc_Sha3_256_Copy
*/
int wc_Sha3_256_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief ハッシュの状態をコピーします。

    \return 0 コピーに成功した場合に返されます。

    \param sha3 コピーするsha3構造体へのポインタ
    \param dst  コピー先のsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
       wc_Sha3_256_Update(sha3, data, len);
       wc_Sha3_256_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Final
    \sa wc_InitSha3_256
    \sa wc_Sha3_256_GetHash
*/
int wc_Sha3_256_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief この関数はSHA3-384を初期化します。これはwc_Sha3_384Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha3 暗号化に使用するsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
        wc_Sha3_384_Update(sha3, data, len);
        wc_Sha3_384_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Update
    \sa wc_Sha3_384_Final
*/
int wc_InitSha3_384(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief 長さlenのバイト配列を継続的にハッシュ化するために呼び出すことができます。

    \return 0 ダイジェストへのデータの追加に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
        wc_Sha3_384_Update(sha3, data, len);
        wc_Sha3_384_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Final
    \sa wc_InitSha3_384
*/
int wc_Sha3_384_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。sha3構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
       wc_Sha3_384_Update(sha3, data, len);
       wc_Sha3_384_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_GetHash
    \sa wc_InitSha3_384
*/
int wc_Sha3_384_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief wc_Sha3構造体をリセットします。注：これはWOLFSSL_TI_HASHが定義されている場合のみサポートされます。

    \return none 戻り値なし。

    \param sha3 解放されるsha3構造体へのポインタ。

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_384(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
        wc_Sha3_384_Update(&sha3, data, len);
        wc_Sha3_384_Final(&sha3, hash);
        wc_Sha3_384_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_384
    \sa wc_Sha3_384_Update
    \sa wc_Sha3_384_Final
*/
void wc_Sha3_384_Free(wc_Sha3*);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。sha3構造体の状態をリセットしません。

    \return 0 ハッシュのコピーに成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_38384ailed");
    }
    else {
       wc_Sha3_384_Update(sha3, data, len);
       wc_Sha3_384_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Final
    \sa wc_InitSha3_384
    \sa wc_Sha3_384_Copy
*/
int wc_Sha3_384_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief ハッシュの状態をコピーします。

    \return 0 コピーに成功した場合に返されます。

    \param sha3 コピーするsha3構造体へのポインタ
    \param dst  コピー先のsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
       wc_Sha3_384_Update(sha3, data, len);
       wc_Sha3_384_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Final
    \sa wc_InitSha3_384
    \sa wc_Sha3_384_GetHash
*/
int wc_Sha3_384_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief この関数はSHA3-512を初期化します。これはwc_Sha3_512Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha3 暗号化に使用するsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
        wc_Sha3_512_Update(sha3, data, len);
        wc_Sha3_512_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Update
    \sa wc_Sha3_512_Final
*/
int wc_InitSha3_512(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief 長さlenのバイト配列を継続的にハッシュ化するために呼び出すことができます。

    \return 0 ダイジェストへのデータの追加に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
        wc_Sha3_512_Update(sha3, data, len);
        wc_Sha3_512_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Final
    \sa wc_InitSha3_512
*/
int wc_Sha3_512_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。sha3構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
       wc_Sha3_512_Update(sha3, data, len);
       wc_Sha3_512_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_GetHash
    \sa wc_InitSha3_512
*/
int wc_Sha3_512_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief wc_Sha3構造体をリセットします。注：これはWOLFSSL_TI_HASHが定義されている場合のみサポートされます。

    \return none 戻り値なし。

    \param sha3 解放されるsha3構造体へのポインタ。

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_512(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
        wc_Sha3_512_Update(&sha3, data, len);
        wc_Sha3_512_Final(&sha3, hash);
        wc_Sha3_512_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_512
    \sa wc_Sha3_512_Update
    \sa wc_Sha3_512_Final
*/
void wc_Sha3_512_Free(wc_Sha3*);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。sha3構造体の状態をリセットしません。

    \return 0 ハッシュのコピーに成功した場合に返されます。

    \param sha3 暗号化に使用するsha3構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
       wc_Sha3_512_Update(sha3, data, len);
       wc_Sha3_512_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Final
    \sa wc_InitSha3_512
    \sa wc_Sha3_512_Copy
*/
int wc_Sha3_512_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief ハッシュの状態をコピーします。

    \return 0 コピーに成功した場合に返されます。

    \param sha3 コピーするsha3構造体へのポインタ
    \param dst  コピー先のsha3構造体へのポインタ

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
       wc_Sha3_512_Update(sha3, data, len);
       wc_Sha3_512_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Final
    \sa wc_InitSha3_512
    \sa wc_Sha3_512_GetHash
*/
int wc_Sha3_512_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief この関数はSHAKE-128を初期化します。これはwc_Shake128Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param shake 暗号化に使用するshake構造体へのポインタ

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
        wc_Shake128_Update(shake, data, len);
        wc_Shake128_Final(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Update
    \sa wc_Shake128_Final
*/
int wc_InitShake128(wc_Shake* shake, void* heap, int devId);

/*!
    \ingroup SHA

    \brief 長さlenのバイト配列を継続的にハッシュ化するために呼び出すことができます。

    \return 0 ダイジェストへのデータの追加に成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
        wc_Shake128_Update(shake, data, len);
        wc_Shake128_Final(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Final
    \sa wc_InitShake128
*/
int wc_Shake128_Update(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。shake構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Update(shake, data, len);
       wc_Shake128_Final(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_GetHash
    \sa wc_InitShake128
*/
int wc_Shake128_Final(wc_Shake* shake, byte* hash);

/*!
    \ingroup SHA

    \brief 長さlenの提供されたバイト配列を吸収するために呼び出されます。段階的に呼び出すことはできません。

    \return 0 データの吸収に成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param data 吸収されるデータ
    \param len 吸収されるデータの長さ

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_128_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Absorb(shake, data, len);
       wc_Shake128_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake128_SqueezeBlocks
    \sa wc_InitShake128
*/
int wc_Shake128_Absorb(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief さらに多くのデータブロックを絞り出します。結果はoutに格納されます。段階的に呼び出すことができます。

    \return 0 絞り出しに成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param hash 出力を保持するバイト配列。
    \param blocks 絞り出すブロックの数。各ブロックはWC_SHA3_128_BLOCK_SIZEバイトの長さです。

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_128_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Absorb(shake, data, len);
       wc_Shake128_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake128_Absorb
    \sa wc_InitShake128
*/
int wc_Shake128_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt);

/*!
    \ingroup SHA

    \brief wc_Shake構造体をリセットします。注：これはWOLFSSL_TI_HASHが定義されている場合のみサポートされます。

    \return none 戻り値なし。

    \param shake 解放されるshake構造体へのポインタ。

    _Example_
    \code
    wc_Shake shake;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake128(&shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
        wc_Shake128_Update(&shake, data, len);
        wc_Shake128_Final(&shake, hash);
        wc_Shake128_Free(&shake);
    }
    \endcode

    \sa wc_InitShake128
    \sa wc_Shake128_Update
    \sa wc_Shake128_Final
*/
void wc_Shake128_Free(wc_Shake*);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。shake構造体の状態をリセットしません。

    \return 0 ハッシュのコピーに成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Update(shake, data, len);
       wc_Shake128_GetHash(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Final
    \sa wc_InitShake128
    \sa wc_Shake128_Copy
*/
int wc_Shake128_GetHash(wc_Shake* shake, byte* hash);

/*!
    \ingroup SHA

    \brief ハッシュの状態をコピーします。

    \return 0 コピーに成功した場合に返されます。

    \param shake コピーするshake構造体へのポインタ
    \param dst  コピー先のshake構造体へのポインタ

    _Example_
    \code
    wc_Shake shake[1];
    wc_Shake shake_dup[1];
    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Update(shake, data, len);
       wc_Shake128_Copy(shake, shake_dup);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Final
    \sa wc_InitShake128
    \sa wc_Shake128_GetHash
*/
int wc_Shake128_Copy(wc_Shake* shake, wc_Shake* dst);

/*!
    \ingroup SHA

    \brief この関数はSHAKE-256を初期化します。これはwc_Shake256Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param shake 暗号化に使用するshake構造体へのポインタ

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
        wc_Shake256_Update(shake, data, len);
        wc_Shake256_Final(shake, hash, sizeof(hash));
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Update
    \sa wc_Shake256_Final
*/
int wc_InitShake256(wc_Shake* shake, void* heap, int devId);

/*!
    \ingroup SHA

    \brief 長さlenのバイト配列を継続的にハッシュ化するために呼び出すことができます。

    \return 0 ダイジェストへのデータの追加に成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
        wc_Shake256_Update(shake, data, len);
        wc_Shake256_Final(shake, hash, sizeof(hash));
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Final
    \sa wc_InitShake256
*/
int wc_Shake256_Update(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。shake構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。
    \param hashLen ハッシュのサイズ（バイト単位）。

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Update(shake, data, len);
       wc_Shake256_Final(shake, hash, sizeof(hash));
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_GetHash
    \sa wc_InitShake256
*/
int wc_Shake256_Final(wc_Shake* shake, byte* hash, word32 hashLen);

/*!
    \ingroup SHA

    \brief 長さlenの提供されたバイト配列を吸収するために呼び出されます。段階的に呼び出すことはできません。

    \return 0 データの吸収に成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param data 吸収されるデータ
    \param len 吸収されるデータの長さ

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_256_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Absorb(shake, data, len);
       wc_Shake256_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake256_SqueezeBlocks
    \sa wc_InitShake256
*/
int wc_Shake256_Absorb(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief さらに多くのデータブロックを絞り出します。結果はoutに格納されます。段階的に呼び出すことができます。

    \return 0 絞り出しに成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param hash 出力を保持するバイト配列。
    \param blocks 絞り出すブロックの数。各ブロックはWC_SHA3_256_BLOCK_SIZEバイトの長さです。

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_256_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Absorb(shake, data, len);
       wc_Shake256_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake256_Absorb
    \sa wc_InitShake256
*/
int wc_Shake256_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt);

/*!
    \ingroup SHA

    \brief wc_Shake構造体をリセットします。注：これはWOLFSSL_TI_HASHが定義されている場合のみサポートされます。

    \return none 戻り値なし。

    \param shake 解放されるshake構造体へのポインタ。

    _Example_
    \code
    wc_Shake shake;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake256(&shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
        wc_Shake256_Update(&shake, data, len);
        wc_Shake256_Final(&shake, hash, sizeof(hash));
        wc_Shake256_Free(&shake);
    }
    \endcode

    \sa wc_InitShake256
    \sa wc_Shake256_Update
    \sa wc_Shake256_Final
*/
void wc_Shake256_Free(wc_Shake*);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。shake構造体の状態をリセットしません。

    \return 0 ハッシュのコピーに成功した場合に返されます。

    \param shake 暗号化に使用するshake構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Update(shake, data, len);
       wc_Shake256_GetHash(shake, hash);
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Final
    \sa wc_InitShake256
    \sa wc_Shake256_Copy
*/
int wc_Shake256_GetHash(wc_Shake* shake, byte* hash);

/*!
    \ingroup SHA

    \brief ハッシュの状態をコピーします。

    \return 0 コピーに成功した場合に返されます。

    \param shake コピーするshake構造体へのポインタ
    \param dst  コピー先のshake構造体へのポインタ

    _Example_
    \code
    wc_Shake shake[1];
    wc_Shake shake_dup[1];
    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Update(shake, data, len);
       wc_Shake256_Copy(shake, shake_dup);
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Final
    \sa wc_InitShake256
    \sa wc_Shake256_GetHash
*/
int wc_Shake256_Copy(wc_Shake* shake, wc_Shake* dst);
