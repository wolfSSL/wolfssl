/*!
    \ingroup SrtpKdf

    \brief この関数はSRTP KDFアルゴリズムを使用して鍵を導出します。

    \return 0 鍵の導出に成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはsaltがNULLの場合に返されます
    \return BAD_FUNC_ARG 鍵の長さが16、24、または32でない場合に返されます。
    \return BAD_FUNC_ARG saltSzが14より大きい場合に返されます。
    \return BAD_FUNC_ARG kdrIdxが-1未満または24より大きい場合に返されます。
    \return MEMORY_E 動的メモリ割り当ての失敗時。

    \param [in] key 暗号化で使用する鍵。
    \param [in] keySz 鍵のサイズ(バイト単位)。
    \param [in] salt ランダムな非秘密値。
    \param [in] saltSz ランダム値のサイズ(バイト単位)。
    \param [in] kdrIdx 鍵導出率。-1の場合kdr = 0、それ以外の場合kdr = 2^kdrIdx。
    \param [in] idx XORするインデックス値。
    \param [out] key1 最初の鍵。ラベル値は0x00。
    \param [in] key1Sz 最初の鍵のサイズ(バイト単位)。
    \param [out] key2 2番目の鍵。ラベル値は0x01。
    \param [in] key2Sz 2番目の鍵のサイズ(バイト単位)。
    \param [out] key3 3番目の鍵。ラベル値は0x02。
    \param [in] key3Sz 3番目の鍵のサイズ(バイト単位)。


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char idx[6] = { ... };
    unsigned char keyE[16];
    unsigned char keyA[20];
    unsigned char keyS[14];
    int kdrIdx = 0; // インデックスのすべてを使用
    int ret;

    ret = wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), kdrIdx, idx,
        keyE, sizeof(keyE), keyA, sizeof(keyA), keyS, sizeof(keyS));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTCP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTCP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTP_KDF(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
        int kdrIdx, const byte* idx, byte* key1, word32 key1Sz, byte* key2,
        word32 key2Sz, byte* key3, word32 key3Sz);

/*!
    \ingroup SrtpKdf

    \brief この関数はSRTCP KDFアルゴリズムを使用して鍵を導出します。

    \return 0 鍵の導出に成功した場合に返されます。
    \return BAD_FUNC_ARG keyまたはsaltがNULLの場合に返されます
    \return BAD_FUNC_ARG 鍵の長さが16、24、または32でない場合に返されます。
    \return BAD_FUNC_ARG saltSzが14より大きい場合に返されます。
    \return BAD_FUNC_ARG kdrIdxが-1未満または24より大きい場合に返されます。
    \return MEMORY_E 動的メモリ割り当ての失敗時。

    \param [in] key 暗号化で使用する鍵。
    \param [in] keySz 鍵のサイズ(バイト単位)。
    \param [in] salt ランダムな非秘密値。
    \param [in] saltSz ランダム値のサイズ(バイト単位)。
    \param [in] kdrIdx 鍵導出率。-1の場合kdr = 0、それ以外の場合kdr = 2^kdrIdx。
    \param [in] idx XORするインデックス値。
    \param [out] key1 最初の鍵。ラベル値は0x00。
    \param [in] key1Sz 最初の鍵のサイズ(バイト単位)。
    \param [out] key2 2番目の鍵。ラベル値は0x01。
    \param [in] key2Sz 2番目の鍵のサイズ(バイト単位)。
    \param [out] key3 3番目の鍵。ラベル値は0x02。
    \param [in] key3Sz 3番目の鍵のサイズ(バイト単位)。


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char idx[4] = { ... };
    unsigned char keyE[16];
    unsigned char keyA[20];
    unsigned char keyS[14];
    int kdrIdx = 0; // インデックスのすべてを使用
    int ret;

    ret = wc_SRTCP_KDF(key, sizeof(key), salt, sizeof(salt), kdrIdx, idx,
        keyE, sizeof(keyE), keyA, sizeof(keyA), keyS, sizeof(keyS));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTCP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTCP_KDF(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
        int kdrIdx, const byte* idx, byte* key1, word32 key1Sz, byte* key2,
        word32 key2Sz, byte* key3, word32 key3Sz);
/*!
    \ingroup SrtpKdf

    \brief この関数はSRTP KDFアルゴリズムを使用してラベル付きの鍵を導出します。

    \return 0 鍵の導出に成功した場合に返されます。
    \return BAD_FUNC_ARG key、salt、またはoutKeyがNULLの場合に返されます
    \return BAD_FUNC_ARG 鍵の長さが16、24、または32でない場合に返されます。
    \return BAD_FUNC_ARG saltSzが14より大きい場合に返されます。
    \return BAD_FUNC_ARG kdrIdxが-1未満または24より大きい場合に返されます。
    \return MEMORY_E 動的メモリ割り当ての失敗時。

    \param [in] key 暗号化で使用する鍵。
    \param [in] keySz 鍵のサイズ(バイト単位)。
    \param [in] salt ランダムな非秘密値。
    \param [in] saltSz ランダム値のサイズ(バイト単位)。
    \param [in] kdrIdx 鍵導出率。-1の場合kdr = 0、それ以外の場合kdr = 2^kdrIdx。
    \param [in] idx XORするインデックス値。
    \param [in] label 鍵を導出する際に使用するラベル。
    \param [out] outKey 導出された鍵。
    \param [in] outKeySz 導出された鍵のサイズ(バイト単位)。


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char idx[6] = { ... };
    unsigned char keyE[16];
    int kdrIdx = 0; // インデックスのすべてを使用
    int ret;

    ret = wc_SRTP_KDF_label(key, sizeof(key), salt, sizeof(salt), kdrIdx, idx,
        WC_SRTP_LABEL_ENCRYPTION, keyE, sizeof(keyE));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTCP_KDF
    \sa wc_SRTCP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTP_KDF_label(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* idx, byte label, byte* outKey,
        word32 outKeySz);
/*!
    \ingroup SrtpKdf

    \brief この関数はSRTCP KDFアルゴリズムを使用してラベル付きの鍵を導出します。

    \return 0 鍵の導出に成功した場合に返されます。
    \return BAD_FUNC_ARG key、salt、またはoutKeyがNULLの場合に返されます
    \return BAD_FUNC_ARG 鍵の長さが16、24、または32でない場合に返されます。
    \return BAD_FUNC_ARG saltSzが14より大きい場合に返されます。
    \return BAD_FUNC_ARG kdrIdxが-1未満または24より大きい場合に返されます。
    \return MEMORY_E 動的メモリ割り当ての失敗時。

    \param [in] key 暗号化で使用する鍵。
    \param [in] keySz 鍵のサイズ(バイト単位)。
    \param [in] salt ランダムな非秘密値。
    \param [in] saltSz ランダム値のサイズ(バイト単位)。
    \param [in] kdrIdx 鍵導出率。-1の場合kdr = 0、それ以外の場合kdr = 2^kdrIdx。
    \param [in] idx XORするインデックス値。
    \param [in] label 鍵を導出する際に使用するラベル。
    \param [out] outKey 導出された鍵。
    \param [in] outKeySz 導出された鍵のサイズ(バイト単位)。


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char idx[4] = { ... };
    unsigned char keyE[16];
    int kdrIdx = 0; // インデックスのすべてを使用
    int ret;

    ret = wc_SRTCP_KDF_label(key, sizeof(key), salt, sizeof(salt), kdrIdx,
        idx, WC_SRTCP_LABEL_ENCRYPTION, keyE, sizeof(keyE));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTCP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTCP_KDF_label(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* idx, byte label, byte* outKey,
        word32 outKeySz);
/*!
    \ingroup SrtpKdf

    \brief この関数はkdr値をSRTP/SRTCP KDF APIで使用するインデックスに変換します。

    \return インデックスとしての鍵導出率。

    \param [in] kdr 変換する鍵導出率。

    _Example_
    \code
    word32 kdr = 0x00000010;
    int kdrIdx;
    int ret;

    kdrIdx = wc_SRTP_KDF_kdr_to_idx(kdr);
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTCP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTCP_KDF_label
*/
int wc_SRTP_KDF_kdr_to_idx(word32 kdr);

/**
 * \brief SP800-56Cオプション1で規定されている単一ステップ鍵導出関数(KDF)を実行します。
 *
 * \param [in] z 入力鍵材料。
 * \param [in] zSz 入力鍵材料のサイズ。
 * \param [in] fixedInfo KDFに含める固定情報。
 * \param [in] fixedInfoSz 固定情報のサイズ。
 * \param [in] derivedSecretSz 導出される秘密の希望サイズ。
 * \param [in] hashType KDFで使用するハッシュアルゴリズム。
 * \param [out] output 導出された秘密を格納するバッファ。
 * \param [in] outputSz 出力バッファのサイズ。
 *

 * \return 0 KDF操作が成功した場合、
 * \return BAD_FUNC_ARG 入力パラメータが無効な場合。
 * \return 負のエラーコード KDF操作が失敗した場合。
 *
 *    _Example_
    \code
    unsigned char z[32] = { ... };
    unsigned char fixedInfo[16] = { ... };
    unsigned char output[32];
    int ret;

    ret = wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo, sizeof(fixedInfo),
        sizeof(output), WC_HASH_TYPE_SHA256, output, sizeof(output));
    if (ret != 0) {
        WOLFSSL_MSG("wc_KDA_KDF_onestep failed");
    }
    \endcode
 */
int wc_KDA_KDF_onestep(const byte* z, word32 zSz,
    const byte* fixedInfo, word32 fixedInfoSz, word32 derivedSecretSz,
    enum wc_HashType hashType, byte* output, word32 outputSz);