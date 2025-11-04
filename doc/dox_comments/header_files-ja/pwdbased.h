/*!
    \ingroup Password

    \brief この関数は、パスワードベース鍵導出関数1(PBKDF1)を実装し、連結されたソルトを持つ入力パスワードをより安全な鍵に変換し、それをoutputに格納します。ユーザーはハッシュ関数としてSHAとMD5のいずれかを選択できます。

    \return 0 入力パスワードから鍵の導出に成功した場合に返されます
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合(有効なタイプはMD5とSHA)、iterationsが1未満の場合、または要求された鍵の長さ(kLen)が提供されたハッシュのハッシュ長より大きい場合に返されます
    \return MEMORY_E SHAまたはMD5オブジェクトのメモリ割り当て中にエラーが発生した場合に返されます

    \param output 生成された鍵を格納するバッファへのポインタ。少なくともkLenの長さである必要があります
    \param passwd 鍵導出に使用するパスワードを含むバッファへのポインタ
    \param pLen 鍵導出に使用するパスワードの長さ
    \param salt 鍵導出に使用するソルトを含むバッファへのポインタ
    \param sLen ソルトの長さ
    \param iterations ハッシュを処理する回数
    \param kLen 導出される鍵の希望の長さ。選択されたハッシュのダイジェストサイズより長くしないでください
    \param hashType 使用するハッシュアルゴリズム。有効な選択肢はWC_MD5とWC_SHAです

    _Example_
    \code
    int ret;
    byte key[WC_MD5_DIGEST_SIZE];
    byte pass[] = { }; // パスワードで初期化
    byte salt[] = { }; // ソルトで初期化

    ret = wc_PBKDF1(key, pass, sizeof(pass), salt, sizeof(salt), 1000,
    sizeof(key), WC_MD5);
    if ( ret != 0 ) {
    	// パスワードからの鍵導出エラー
    }
    \endcode

    \sa wc_PBKDF2
    \sa wc_PKCS12_PBKDF
*/
int wc_PBKDF1(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int hashType);

/*!
    \ingroup Password

    \brief この関数は、パスワードベース鍵導出関数2(PBKDF2)を実装し、連結されたソルトを持つ入力パスワードをより安全な鍵に変換し、それをoutputに格納します。ユーザーは、WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512を含む、サポートされているHMACハッシュ関数のいずれかを選択できます。

    \return 0 入力パスワードから鍵の導出に成功した場合に返されます
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合、またはiterationsが1未満の場合に返されます
    \return MEMORY_E HMACオブジェクトのメモリ割り当て中にエラーが発生した場合に返されます

    \param output 生成された鍵を格納するバッファへのポインタ。kLenの長さである必要があります
    \param passwd 鍵導出に使用するパスワードを含むバッファへのポインタ
    \param pLen 鍵導出に使用するパスワードの長さ
    \param salt 鍵導出に使用するソルトを含むバッファへのポインタ
    \param sLen ソルトの長さ
    \param iterations ハッシュを処理する回数
    \param kLen 導出される鍵の希望の長さ
    \param hashType 使用するハッシュアルゴリズム。有効な選択肢は、WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512です

    _Example_
    \code
    int ret;
    byte key[64];
    byte pass[] = { }; // パスワードで初期化
    byte salt[] = { }; // ソルトで初期化

    ret = wc_PBKDF2(key, pass, sizeof(pass), salt, sizeof(salt), 2048, sizeof(key),
    WC_SHA512);
    if ( ret != 0 ) {
    	// パスワードからの鍵導出エラー
    }
    \endcode

    \sa wc_PBKDF1
    \sa wc_PKCS12_PBKDF
*/
int wc_PBKDF2(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int hashType);

/*!
    \ingroup Password

    \brief この関数は、RFC 7292付録Bに記述されているパスワードベース鍵導出関数(PBKDF)を実装します。この関数は、連結されたソルトを持つ入力パスワードをより安全な鍵に変換し、それをoutputに格納します。ユーザーは、WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512を含む、サポートされているHMACハッシュ関数のいずれかを選択できます。

    \return 0 入力パスワードから鍵の導出に成功した場合に返されます
    \return BAD_FUNC_ARG 無効なハッシュタイプが指定された場合、iterationsが1未満の場合、または要求された鍵の長さ(kLen)が提供されたハッシュのハッシュ長より大きい場合に返されます
    \return MEMORY_E メモリ割り当て中にエラーが発生した場合に返されます
    \return MP_INIT_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_READ_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_CMP_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_INVMOD_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_EXPTMOD_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_MOD_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_MUL_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_ADD_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_MULMOD_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_TO_E 鍵生成中にエラーが発生した場合に返される可能性があります
    \return MP_MEM 鍵生成中にエラーが発生した場合に返される可能性があります

    \param output 生成された鍵を格納するバッファへのポインタ。kLenの長さである必要があります
    \param passwd 鍵導出に使用するパスワードを含むバッファへのポインタ
    \param passLen 鍵導出に使用するパスワードの長さ
    \param salt 鍵導出に使用するソルトを含むバッファへのポインタ
    \param saltLen ソルトの長さ
    \param iterations ハッシュを処理する回数
    \param kLen 導出される鍵の希望の長さ
    \param hashType 使用するハッシュアルゴリズム。有効な選択肢は、WC_MD5、WC_SHA、WC_SHA256、WC_SHA384、WC_SHA512、WC_SHA3_224、WC_SHA3_256、WC_SHA3_384、またはWC_SHA3_512です
    \param id 鍵生成の目的を示すバイト識別子。鍵出力を多様化するために使用され、次のように割り当てる必要があります。ID=1: 疑似乱数ビットは、暗号化または復号を実行するための鍵材料として使用されます。ID=2: 疑似乱数ビットは、暗号化または復号のためのIV(初期値)として使用されます。ID=3: 疑似乱数ビットは、MAC処理のための完全性鍵として使用されます。

    _Example_
    \code
    int ret;
    byte key[64];
    byte pass[] = { }; // パスワードで初期化
    byte salt[] = { }; // ソルトで初期化

    ret = wc_PKCS512_PBKDF(key, pass, sizeof(pass), salt, sizeof(salt), 2048,
    sizeof(key), WC_SHA512, 1);
    if ( ret != 0 ) {
    	// パスワードからの鍵導出エラー
    }
    \endcode

    \sa wc_PBKDF1
    \sa wc_PBKDF2
*/
int wc_PKCS12_PBKDF(byte* output, const byte* passwd, int passLen,
                            const byte* salt, int saltLen, int iterations,
                            int kLen, int hashType, int id);