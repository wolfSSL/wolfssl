/*!
    \ingroup RIPEMD

    \brief この関数は、ripemdのダイジェスト、バッファ、loLenおよびhiLenを初期化することで、ripemd構造体を初期化します。

    \return 0 関数の実行が成功した場合に返されます。RipeMd構造体が初期化されます。
    \return BAD_FUNC_ARG RipeMd構造体がNULLの場合に返されます。

    \param ripemd 初期化するripemd構造体へのポインタ

    _Example_
    \code
    RipeMd md;
    int ret;
    ret = wc_InitRipeMd(&md);
    if (ret != 0) {
    	// 失敗ケース
    }
    \endcode

    \sa wc_RipeMdUpdate
    \sa wc_RipeMdFinal
*/
int wc_InitRipeMd(RipeMd*);

/*!
    \ingroup RIPEMD

    \brief この関数は、入力データのRipeMdダイジェストを生成し、結果をripemd->digestバッファに格納します。wc_RipeMdUpdateを実行した後、生成されたripemd->digestを既知の認証タグと比較して、メッセージの真正性を検証する必要があります。

    \return 0 関数の実行が成功した場合に返されます。
    \return BAD_FUNC_ARG RipeMd構造体がNULLの場合、またはdataがNULLでlenがゼロでない場合に返されます。この関数は、dataがNULLでlenが0の場合は実行されるべきです。

    \param ripemd wc_InitRipeMdで初期化されるripemd構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len データのサイズ(バイト単位)

    _Example_
    \code
    const byte* data; // ハッシュ化されるデータ
    ....
    RipeMd md;
    int ret;
    ret = wc_InitRipeMd(&md);
    if (ret == 0) {
    ret = wc_RipeMdUpdate(&md, plain, sizeof(plain));
    if (ret != 0) {
	// 失敗ケース …
    \endcode

    \sa wc_InitRipeMd
    \sa wc_RipeMdFinal
*/
int wc_RipeMdUpdate(RipeMd* ripemd, const byte* data, word32 len);

/*!
    \ingroup RIPEMD

    \brief この関数は、計算されたダイジェストをhashにコピーします。部分的にハッシュ化されていないブロックがある場合、このメソッドはブロックを0でパディングし、hashにコピーする前にそのブロックのラウンドをダイジェストに含めます。ripemdの状態はリセットされます。

    \return 0 関数の実行が成功した場合に返されます。RipeMd構造体の状態がリセットされました。
    \return BAD_FUNC_ARG RipeMd構造体またはhashパラメータがNULLの場合に返されます。

    \param ripemd wc_InitRipeMdで初期化され、wc_RipeMdUpdateからのハッシュを含むripemd構造体へのポインタ。状態はリセットされます
    \param hash ダイジェストをコピーするバッファ。RIPEMD_DIGEST_SIZEバイトである必要があります

    _Example_
    \code
    RipeMd md;
    int ret;
    byte   digest[RIPEMD_DIGEST_SIZE];
    const byte* data; // ハッシュ化されるデータ
    ...
    ret = wc_InitRipeMd(&md);
    if (ret == 0) {
    ret = wc_RipeMdUpdate(&md, plain, sizeof(plain));
    	if (ret != 0) {
    		// RipeMd更新失敗ケース
    }
    ret = wc_RipeMdFinal(&md, digest);
    if (ret != 0) {
    	// RipeMd Final失敗ケース
    }...
    \endcode

    \sa none
*/
int wc_RipeMdFinal(RipeMd* ripemd, byte* hash);
