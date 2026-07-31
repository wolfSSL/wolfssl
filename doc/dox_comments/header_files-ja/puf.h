/*!
    \ingroup PUF

    完全なベアメタルの実装例(NUCLEO-H563ZIで動作確認済み)については、
    https://github.com/wolfSSL/wolfssl-examples/tree/master/puf を参照してください。
*/

/*!
    \ingroup PUF

    \brief wc_PufCtx構造体を初期化し、すべてのフィールドをゼロクリアします。他のPUF操作を行う前に呼び出さなければなりません。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxがNULLの場合に返されます

    \param ctx 初期化するwc_PufCtx構造体へのポインタ

    _Example_
    \code
    wc_PufCtx ctx;
    ret = wc_PufInit(&ctx);
    \endcode

    \sa wc_PufReadSram
    \sa wc_PufEnroll
    \sa wc_PufZeroize
*/
int wc_PufInit(wc_PufCtx* ctx);

/*!
    \ingroup PUF

    \brief 生のSRAMデータをPUFコンテキストに読み込みます。電源投入時の状態を保持するため、sramAddrはNOLOADリンカセクションを指している必要があります。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxまたはsramAddrがNULLの場合に返されます
    \return PUF_READ_E sramSzがWC_PUF_RAW_BYTES未満の場合に返されます

    \param ctx wc_PufCtx構造体へのポインタ
    \param sramAddr 生のSRAMメモリ領域へのポインタ
    \param sramSz SRAMバッファのサイズ(WC_PUF_RAW_BYTES以上でなければなりません)

    _Example_
    \code
    __attribute__((section(".puf_sram")))
    static volatile uint8_t puf_sram[256];
    wc_PufReadSram(&ctx, (const byte*)puf_sram, sizeof(puf_sram));
    \endcode

    \sa wc_PufInit
    \sa wc_PufEnroll
    \sa wc_PufReconstruct
*/
int wc_PufReadSram(wc_PufCtx* ctx, const byte* sramAddr, word32 sramSz);

/*!
    \ingroup PUF

    \brief PUFのエンロールメント(登録)を実行します。BCH(127,64,t=10)を用いて生のSRAMを符号化し、公開ヘルパーデータを生成します。エンロールメント後、コンテキストは鍵導出とアイデンティティ取得に使用できる状態になります。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxがNULLの場合に返されます
    \return PUF_ENROLL_E エンロールメントが失敗した場合に返されます

    \param ctx wc_PufCtxへのポインタ(SRAMデータが読み込まれていなければなりません)

    _Example_
    \code
    wc_PufEnroll(&ctx);
    XMEMCPY(helperData, ctx.helperData, WC_PUF_HELPER_BYTES);
    \endcode

    \sa wc_PufReadSram
    \sa wc_PufReconstruct
    \sa wc_PufDeriveKey
*/
int wc_PufEnroll(wc_PufCtx* ctx);

/*!
    \ingroup PUF

    \brief 保存されたヘルパーデータを用いて、ノイズを含むSRAMから安定したPUFビットを再構成します。BCH誤り訂正(t=10)により、127ビットの符号語あたり最大10ビットの反転を訂正できます。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxまたはhelperDataがNULLの場合に返されます
    \return PUF_RECONSTRUCT_E 失敗した場合に返されます(ビット誤りが多すぎる、またはhelperSzが小さすぎる)

    \param ctx wc_PufCtxへのポインタ(SRAMデータが読み込まれていなければなりません)
    \param helperData 以前のエンロールメントで得られたヘルパーデータへのポインタ
    \param helperSz ヘルパーデータのサイズ(WC_PUF_HELPER_BYTES以上)

    _Example_
    \code
    wc_PufReconstruct(&ctx, helperData, sizeof(helperData));
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufDeriveKey
    \sa wc_PufGetIdentity
*/
int wc_PufReconstruct(wc_PufCtx* ctx, const byte* helperData, word32 helperSz);

/*!
    \ingroup PUF

    \brief HKDFを用いて、PUFの安定ビットから暗号鍵を導出します。デフォルトではSHA-256を、WC_PUF_SHA3が定義されている場合はSHA3-256を使用します。infoパラメータは複数の鍵を導出する際のドメイン分離を提供します。HAVE_HKDFが必要です。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxまたはkeyがNULLの場合、あるいはkeySzが0の場合に返されます
    \return PUF_DERIVE_KEY_E PUFが準備できていない場合、またはHKDFが失敗した場合に返されます

    \param ctx wc_PufCtxへのポインタ(エンロールメント済みまたは再構成済みでなければなりません)
    \param info ドメイン分離のための任意のコンテキスト情報(NULLでも構いません。NULLの場合、infoSzは0として扱われます)
    \param infoSz infoのサイズ(バイト単位)
    \param key 導出した鍵を格納する出力バッファ
    \param keySz 導出する鍵のサイズ(バイト単位)

    _Example_
    \code
    byte key[32];
    const byte info[] = "my-app-key";
    wc_PufDeriveKey(&ctx, info, sizeof(info), key, sizeof(key));
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufReconstruct
    \sa wc_PufGetIdentity
*/
int wc_PufDeriveKey(wc_PufCtx* ctx, const byte* info, word32 infoSz,
                    byte* key, word32 keySz);

/*!
    \ingroup PUF

    \brief デバイスのアイデンティティハッシュ(安定ビットのSHA-256またはSHA3-256)を取得します。同一のデバイスであれば、常に同じ値が得られます。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxまたはidがNULLの場合に返されます
    \return PUF_IDENTITY_E PUFが準備できていない場合、またはidSzがWC_PUF_ID_SZ未満の場合に返されます

    \param ctx wc_PufCtxへのポインタ(エンロールメント済みまたは再構成済みでなければなりません)
    \param id アイデンティティハッシュを格納する出力バッファ
    \param idSz idバッファのサイズ(WC_PUF_ID_SZ(32バイト)以上)

    _Example_
    \code
    byte identity[WC_PUF_ID_SZ];
    wc_PufGetIdentity(&ctx, identity, sizeof(identity));
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufReconstruct
    \sa wc_PufDeriveKey
*/
int wc_PufGetIdentity(wc_PufCtx* ctx, byte* id, word32 idSz);

/*!
    \ingroup PUF

    \brief ForceZeroを用いて、PUFコンテキスト内のすべての機密データを安全にゼロクリアします。PUFが不要になった時点で呼び出してください。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxがNULLの場合に返されます

    \param ctx ゼロクリアするwc_PufCtxへのポインタ

    _Example_
    \code
    wc_PufZeroize(&ctx);
    \endcode

    \sa wc_PufInit
*/
int wc_PufZeroize(wc_PufCtx* ctx);

/*!
    \ingroup PUF

    \brief ハードウェアなしでテストを行うために、合成したSRAMテストデータを注入します。WOLFSSL_PUF_TESTが定義されている場合にのみ利用できます。

    \return 0 成功した場合に返されます
    \return BAD_FUNC_ARG ctxまたはdataがNULLの場合に返されます
    \return PUF_READ_E szがWC_PUF_RAW_BYTES未満の場合に返されます

    \param ctx wc_PufCtxへのポインタ
    \param data 合成SRAMデータへのポインタ
    \param sz dataのサイズ(WC_PUF_RAW_BYTES(256バイト)以上)

    _Example_
    \code
    byte testSram[WC_PUF_RAW_BYTES];
    wc_PufSetTestData(&ctx, testSram, sizeof(testSram));
    \endcode

    \sa wc_PufInit
    \sa wc_PufReadSram
*/
int wc_PufSetTestData(wc_PufCtx* ctx, const byte* data, word32 sz);
