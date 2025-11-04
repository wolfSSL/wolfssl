/*!
    \ingroup wolfCrypt

    \brief この関数は、提供されたwc_HashTypeのOIDを返します。

    \return OID 0より大きい値を返します
    \return HASH_TYPE_E ハッシュタイプがサポートされていません。
    \return BAD_FUNC_ARG 提供された引数の1つが正しくありません。

    \param hash_type "WC_HASH_TYPE_SHA256"などの"enum wc_HashType"からのハッシュタイプ。

    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int oid = wc_HashGetOID(hash_type);
    if (oid > 0) {
    	// 成功
    }
    \endcode

    \sa wc_HashGetDigestSize
    \sa wc_Hash
*/
int wc_HashGetOID(enum wc_HashType hash_type);

/*!
    \ingroup wolfCrypt

    \brief この関数は、hash_typeのダイジェスト(出力)のサイズを返します。返されるサイズは、wc_Hashに提供される出力バッファが十分な大きさであることを確認するために使用されます。

    \return Success 正の戻り値は、ハッシュのダイジェストサイズを示します。
    \return Error hash_typeがサポートされていない場合、HASH_TYPE_Eを返します。
    \return Failure 無効なhash_typeが使用された場合、BAD_FUNC_ARGを返します。

    \param hash_type "WC_HASH_TYPE_SHA256"などの"enum wc_HashType"からのハッシュタイプ。

    _Example_
    \code
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
    WOLFSSL_MSG("Invalid hash type/len");
    return BAD_FUNC_ARG;
    }
    \endcode

    \sa wc_Hash
*/
int wc_HashGetDigestSize(enum wc_HashType hash_type);

/*!
    \ingroup wolfCrypt

    \brief この関数は、提供されたデータバッファに対してハッシュを実行し、提供されたハッシュバッファに結果を返します。

    \return 0 成功、それ以外はエラー(BAD_FUNC_ARGやBUFFER_Eなど)。

    \param hash_type "WC_HASH_TYPE_SHA256"などの"enum wc_HashType"からのハッシュタイプ。
    \param data ハッシュ化するデータを含むバッファへのポインタ。
    \param data_len データバッファの長さ。
    \param hash 最終ハッシュを出力するために使用されるバッファへのポインタ。
    \param hash_len ハッシュバッファの長さ。

    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len > 0) {
        int ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
        if(ret == 0) {
		    // 成功
        }
    }
    \endcode

    \sa wc_HashGetDigestSize
*/
int wc_Hash(enum wc_HashType hash_type,
    const byte* data, word32 data_len,
    byte* hash, word32 hash_len);

/*!
    \ingroup MD5

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 データのハッシュ化に成功した場合に返されます。
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    const byte* data;
    word32 data_len;
    byte* hash;
    int ret;
    ...
    ret = wc_Md5Hash(data, data_len, hash);
    if (ret != 0) {
         // Md5ハッシュ失敗のケース。
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int wc_Md5Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 正常に….の場合に返されます。
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
int wc_ShaHash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 成功
    \return <0 エラー

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha224
    \sa wc_Sha224Update
    \sa wc_Sha224Final
*/
int wc_Sha224Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 正常に…の場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
int wc_Sha256Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 データのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
int wc_Sha384Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 入力されたデータのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
int wc_Sha512Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 データのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_224
    \sa wc_Sha3_224_Update
    \sa wc_Sha3_224_Final
*/
int wc_Sha3_224Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 データのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_256
    \sa wc_Sha3_256_Update
    \sa wc_Sha3_256_Final
*/
int wc_Sha3_256Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 データのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_384
    \sa wc_Sha3_384_Update
    \sa wc_Sha3_384_Final
*/
int wc_Sha3_384Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 入力されたデータのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_512
    \sa wc_Sha3_512_Update
    \sa wc_Sha3_512_Final
*/
int wc_Sha3_512Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 入力されたデータのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_InitShake128
    \sa wc_Shake128_Update
    \sa wc_Shake128_Final
*/
int wc_Shake128Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief 便利な関数で、すべてのハッシュ処理を行い、結果をhashに格納します。

    \return 0 入力されたデータのハッシュ化に成功した場合に返されます
    \return Memory_E メモリエラー、メモリを割り当てられません。これは小さいスタックオプションが有効な場合にのみ可能です。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_InitShake256
    \sa wc_Shake256_Update
    \sa wc_Shake256_Final
*/
int wc_Shake256Hash(const byte* data, word32 len, byte* hash);