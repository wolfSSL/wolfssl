/*!
    \ingroup Memory

    \brief この関数はmalloc()に似ていますが、wolfSSLが使用するように設定されたメモリ割り当て関数を呼び出します。デフォルトでは、wolfSSLはmalloc()を使用します。これはwolfSSLメモリ抽象化レイヤーを使用して変更できます - wolfSSL_SetAllocators()を参照してください。wolfSSL_Mallocは直接wolfSSLによって呼び出されるのではなく、代わりにマクロXMALLOCによって呼び出されることに注意してください。
    デフォルトのビルドでは、sizeパラメータのみが存在します。WOLFSSL_STATIC_MEMORYビルドを使用している場合は、heapとtypeパラメータが含まれます。

    \return pointer 成功した場合、この関数は割り当てられたメモリへのポインタを返します。
    \return error エラーがある場合、NULLが返されます。

    \param size 割り当てるメモリのバイト単位のサイズ。
    \param heap メモリに使用するヒープヒント。NULLにできます。
    \param type 動的タイプ（types.hのDYNAMIC_TYPE_リストを参照）。

    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    \endcode

    \sa wolfSSL_Free
    \sa wolfSSL_Realloc
    \sa wolfSSL_SetAllocators
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
void* wolfSSL_Malloc(size_t size, void* heap, int type);

/*!
    \ingroup Memory

    \brief この関数はfree()に似ていますが、wolfSSLが使用するように設定されたメモリ解放関数を呼び出します。デフォルトでは、wolfSSLはfree()を使用します。これはwolfSSLメモリ抽象化レイヤーを使用して変更できます - wolfSSL_SetAllocators()を参照してください。wolfSSL_Freeは直接wolfSSLによって呼び出されるのではなく、代わりにマクロXFREEによって呼び出されることに注意してください。
    デフォルトのビルドでは、ptrパラメータのみが存在します。WOLFSSL_STATIC_MEMORYビルドを使用している場合は、heapとtypeパラメータが含まれます。

    \return none 戻り値なし。

    \param ptr 解放するメモリへのポインタ。
    \param heap メモリに使用するヒープヒント。NULLにできます。
    \param type 動的タイプ（types.hのDYNAMIC_TYPE_リストを参照）。

    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    // 必要に応じてデータを処理
    ...
    if(tenInts) {
    	wolfSSL_Free(tenInts, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    \endcode

    \sa wolfSSL_Alloc
    \sa wolfSSL_Realloc
    \sa wolfSSL_SetAllocators
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
void  wolfSSL_Free(void *ptr, void* heap, int type);

/*!
    \ingroup Memory

    \brief この関数はrealloc()に似ていますが、wolfSSLが使用するように設定されたメモリ再割り当て関数を呼び出します。デフォルトでは、wolfSSLはrealloc()を使用します。これはwolfSSLメモリ抽象化レイヤーを使用して変更できます - wolfSSL_SetAllocators()を参照してください。
    wolfSSL_Reallocは直接wolfSSLによって呼び出されるのではなく、代わりにマクロXREALLOCによって呼び出されることに注意してください。デフォルトのビルドでは、sizeパラメータのみが存在します。WOLFSSL_STATIC_MEMORYビルドを使用している場合は、heapとtypeパラメータが含まれます。

    \return pointer 成功した場合、この関数は再割り当てされたメモリへのポインタを返します。これはptrと同じポインタである場合もあれば、新しいポインタの場所である場合もあります。
    \return Null エラーがある場合、NULLが返されます。

    \param ptr 再割り当てする、以前に割り当てられたメモリへのポインタ。
    \param size 割り当てるバイト数。
    \param heap メモリに使用するヒープヒント。NULLにできます。
    \param type 動的タイプ（types.hのDYNAMIC_TYPE_リストを参照）。

    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    int* twentyInts = (int*)wolfSSL_Realloc(tenInts, sizeof(int)*20);
    \endcode

    \sa wolfSSL_Free
    \sa wolfSSL_Malloc
    \sa wolfSSL_SetAllocators
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
void* wolfSSL_Realloc(void *ptr, size_t size, void* heap, int type);

/*!
    \ingroup Memory

    \brief この関数は、wolfSSLが使用する割り当て関数を登録します。デフォルトでは、システムがサポートしている場合、malloc/freeとreallocが使用されます。この関数を使用すると、ユーザーは実行時に独自のメモリハンドラをインストールできます。

    \return Success 成功した場合、この関数は0を返します。
    \return BAD_FUNC_ARG 関数ポインタが提供されていない場合に返されるエラー。

    \param malloc_function wolfSSLが使用するメモリ割り当て関数。関数シグネチャは上記のwolfSSL_Malloc_cbプロトタイプと一致する必要があります。
    \param free_function wolfSSLが使用するメモリ解放関数。関数シグネチャは上記のwolfSSL_Free_cbプロトタイプと一致する必要があります。
    \param realloc_function wolfSSLが使用するメモリ再割り当て関数。関数シグネチャは上記のwolfSSL_Realloc_cbプロトタイプと一致する必要があります。

    _Example_
    \code
    static void* MyMalloc(size_t size)
    {
    	// カスタムmalloc関数
    }

    static void MyFree(void* ptr)
    {
    	// カスタムfree関数
    }

    static void* MyRealloc(void* ptr, size_t size)
    {
    	// カスタムrealloc関数
    }

    // カスタムメモリ関数をwolfSSLに登録
    int ret = wolfSSL_SetAllocators(MyMalloc, MyFree, MyRealloc);
    if (ret != 0) {
    	// メモリ関数の設定に失敗
    }
    \endcode

    \sa none
*/
int wolfSSL_SetAllocators(wolfSSL_Malloc_cb mf, wolfSSL_Free_cb ff,
                                      wolfSSL_Realloc_cb rf);

/*!
    \ingroup Memory

    \brief この関数は、静的メモリ機能が使用されている場合に利用可能です（--enable-staticmemory）。メモリ「バケット」の最適なバッファサイズを提供します。これにより、パーティション化された後に余分な未使用メモリが残らないようにバッファサイズを計算する方法が提供されます。この関数の非_exバージョンでは、コンパイル時に設定されたデフォルトのバケットと配布リストが使用されます。
    返される値が正の場合、使用する計算されたバッファサイズです。

    \return Success バッファサイズの計算が正常に完了すると、正の値が返されます。この返される値は最適なバッファサイズです。
    \return Failure すべての負の値はエラーケースと見なされます。

    \param buffer バッファへのポインタ。
    \param size バッファのサイズ。
    \param type 希望するメモリタイプ、つまりWOLFMEM_GENERALまたはWOLFMEM_IO_POOL。

    _Example_
    \code
    byte buffer[1000];
    word32 size = sizeof(buffer);
    int optimum;

    optimum = wolfSSL_StaticBufferSz(buffer, size, WOLFMEM_GENERAL);
    if (optimum < 0) { //エラーケースを処理 }
    printf("すべてのメモリを利用するための最適なバッファサイズは %d です\n",
    optimum);
    ...
    \endcode

    \sa wolfSSL_Malloc
    \sa wolfSSL_Free
*/
int wolfSSL_StaticBufferSz(byte* buffer, word32 sz, int flag);

/*!
    \ingroup Memory

    \brief この関数は、静的メモリ機能が使用されている場合に利用可能です（--enable-staticmemory）。メモリの各パーティションに必要なパディングのサイズを提供します。このパディングサイズは、メモリ管理構造体を含むために必要なサイズと、メモリアライメントのための追加分になります。

    \return メモリパディングの計算が成功すると、戻り値は正の値になります。
    \return すべての負の値はエラーケースと見なされます。

    \param none パラメータなし。

    _Example_
    \code
    int padding;
    padding = wolfSSL_MemoryPaddingSz();
    if (padding < 0) { //エラーケースを処理 }
    printf("メモリの各「バケット」に必要なパディングサイズは %d です\n",
    padding);
    // IO POOLサイズのバッファの計算は、バケット数
    // × (padding + WOLFMEM_IO_SZ)
    ...
    \endcode

    \sa wolfSSL_Malloc
    \sa wolfSSL_Free
*/
int wolfSSL_MemoryPaddingSz(void);

/*!
    \ingroup Memory

    \brief この関数は、CTXのために静的メモリを確保するために使用されます。確保されたメモリは、CTXの存続期間中およびCTXから作成されたすべてのSSLオブジェクトに使用されます。NULLのctxポインタとwolfSSL_method_func関数を渡すことにより、CTX自体の作成も静的メモリを使用します。wolfSSL_method_funcは、WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);の関数シグネチャを持ちます。
    maxに0を渡すと、設定されていないかのように動作し、最大同時使用制限が適用されません。
    渡されるflag値は、メモリの使用方法と動作中の動作を決定します。
    利用可能なフラグは次のとおりです。

    0 - デフォルトの一般メモリ

    WOLFMEM_IO_POOL - メッセージの送受信時の入出力バッファに使用されます。一般メモリをオーバーライドするため、渡されたバッファ内のすべてのメモリがIOに使用されます。
    WOLFMEM_IO_FIXED - WOLFMEM_IO_POOLと同じですが、各SSLは存続期間中に2つのバッファを保持します。
    WOLFMEM_TRACK_STATS - 各SSLは実行中にメモリ統計を追跡します。

    \return 成功した場合、SSL_SUCCESSが返されます。
    \return すべての失敗した戻り値は0未満またはSSL_FAILUREと等しくなります。

    \param ctx WOLFSSL_CTX構造体へのポインタのアドレス。
    \param method プロトコルを作成する関数。（ctxもNULLでない場合はNULLである必要があります）
    \param buf すべての操作に使用するメモリ。
    \param sz 渡されるメモリバッファのサイズ。
    \param flag メモリのタイプ。
    \param max 最大同時操作数。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    unsigned char IO[MAX];
    int IOSz = MAX;
    int flag = WOLFMEM_IO_FIXED | WOLFMEM_TRACK_STATS;
    ...
    // 静的メモリを使用してctxも作成、使用する一般メモリから開始
    ctx = NULL:
    ret = wolfSSL_CTX_load_static_memory(&ctx, wolfSSLv23_server_method_ex, memory, memorySz, 0,
    MAX_CONCURRENT_HANDSHAKES);
    if (ret != SSL_SUCCESS) {
    // エラーケースを処理
    }
    // IOで使用するメモリをロード
    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL, IO, IOSz, flag, MAX_CONCURRENT_IO);
    if (ret != SSL_SUCCESS) {
    // エラーケースを処理
    }
    ...
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_is_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx, wolfSSL_method_func method,
        unsigned char* buf, unsigned int sz, int flag, int max);

/*!
    \ingroup Memory

    \brief この関数は接続の動作を変更せず、静的メモリ使用に関する情報を収集するためにのみ使用されます。

    \return CTXに静的メモリを使用している場合は1の値が返されます。
    \return 静的メモリを使用していない場合は0が返されます。

    \param ctx wolfSSL_CTX_new()を使用して作成されたWOLFSSL_CTX構造体へのポインタ。
    \param mem_stats 静的メモリ使用に関する情報を保持する構造体。

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int ret;
    WOLFSSL_MEM_STATS mem_stats;
    ...
    //CTXでの静的メモリに関する情報を取得

    ret = wolfSSL_CTX_is_static_memory(ctx, &mem_stats);

    if (ret == 1) {
        // 静的メモリを使用しているケースを処理
        // mem_statsの要素を出力または検査
    }

    if (ret == 0) {
        //ctxが静的メモリを使用していないケースを処理
    }
    ...
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_load_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx, WOLFSSL_MEM_STATS* mem_stats);

/*!
    \ingroup Memory

    \brief wolfSSL_is_static_memoryは、SSLの静的メモリ使用に関する情報を収集するために使用されます。戻り値は、静的メモリが使用されているかどうかを示し、WOLFSSL_MEM_CONN_STATSは、静的メモリをロードする際に親CTXにWOLFMEM_TRACK_STATSフラグが渡された場合にのみ入力されます。

    \return CTXに静的メモリを使用している場合は1の値が返されます。
    \return 静的メモリを使用していない場合は0が返されます。

    \param ssl wolfSSL_new()を使用して作成されたWOLFSSL構造体へのポインタ。
    \param mem_stats 静的メモリ使用を含む構造体。

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    WOLFSSL_MEM_CONN_STATS mem_stats;

    ...

    ret = wolfSSL_is_static_memory(ssl, mem_stats);

    if (ret == 1) {
        // 静的メモリの場合のケースを処理
        // WOLFMEM_TRACK_STATSフラグがある場合はmem_statsの要素を調査
    }
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_is_static_memory
*/
int wolfSSL_is_static_memory(WOLFSSL* ssl, WOLFSSL_MEM_CONN_STATS* mem_stats);

/*!
    \ingroup Memory

    \brief この関数は、wolfCrypt使用のために静的メモリを確保するために使用されます。作成されたヒープヒントを関数に渡すことでメモリを使用できます。この例は、wc_InitRng_exを呼び出すときです。渡されるflag値は、メモリの使用方法と動作中の動作を決定します。一般的に、wolfCrypt操作はWOLFMEM_GENERALプールからメモリを使用します。
    利用可能なフラグは次のとおりです。

    WOLFMEM_GENERAL - デフォルトの一般メモリ

    WOLFMEM_IO_POOL - メッセージの送受信時の入出力バッファに使用されます。一般メモリをオーバーライドするため、渡されたバッファ内のすべてのメモリがIOに使用されます。
    WOLFMEM_IO_FIXED - WOLFMEM_IO_POOLと同じですが、各SSLは存続期間中に2つのバッファを保持します。
    WOLFMEM_TRACK_STATS - 各SSLは実行中にメモリ統計を追跡します。

    \return none この関数は値を返しません。

    \param phint 使用するWOLFSSL_HEAP_HINT構造体。
    \param buf すべての操作に使用するメモリ。
    \param sz 渡されるメモリバッファのサイズ。
    \param flag メモリのタイプ。
    \param max 最大同時操作数（ハンドシェイク、IO）。

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    int flag = WOLFMEM_GENERAL | WOLFMEM_TRACK_STATS;
    ...

    // 使用するメモリをロード

    ret = wc_LoadStaticMemory(&hint, memory, memorySz, flag, 0);
    if (ret != SSL_SUCCESS) {
        // エラーケースを処理
    }
    ...

    ret = wc_InitRng_ex(&rng, hint, 0);

    // ret値をチェック
    \endcode

    \sa none
*/
int wc_LoadStaticMemory(WOLFSSL_HEAP_HINT** pHint, unsigned char* buf,
                unsigned int sz, int flag, int max);

/*!
    \ingroup Memory

    \brief この関数は、カスタムバケットサイズと配分を使用してwolfCrypt使用のために静的メモリを確保するために使用されます。作成されたヒープヒントを関数に渡すことでメモリを使用できます。この拡張バージョンでは、デフォルトの事前定義されたサイズを使用する代わりに、カスタムバケットサイズと配分を使用できます。

    \return none この関数は値を返しません。

    \param pHint 初期化するWOLFSSL_HEAP_HINTハンドル。
    \param listSz サイズリストと分布リストのエントリ数。
    \param sizeList 使用するバケットサイズの配列。
    \param distList sizeListに対応する分布リスト。
    \param buf すべての操作に使用するメモリ。
    \param sz 渡されるメモリバッファのサイズ。
    \param flag メモリのタイプ。
    \param max 最大同時操作数（ハンドシェイク、IO）。

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    int flag = WOLFMEM_GENERAL | WOLFMEM_TRACK_STATS;
    const word32 sizeList[] = {64, 128, 256, 512, 1024};
    const word32 distList[] = {1, 1, 1, 1, 1};
    unsigned int listSz = (unsigned int)(sizeof(sizeList)/
                                         sizeof(sizeList[0]));
    ...

    // カスタムバケットサイズで使用するメモリをロード

    ret = wc_LoadStaticMemory_ex(&hint, listSz, sizeList, distList,
                                 memory, memorySz, flag, 0);
    if (ret != SSL_SUCCESS) {
        // エラーケースを処理
    }
    ...

    ret = wc_InitRng_ex(&rng, hint, 0);

    // ret値をチェック
    \endcode

    \sa wc_LoadStaticMemory
    \sa wc_UnloadStaticMemory
*/
int wc_LoadStaticMemory_ex(WOLFSSL_HEAP_HINT** pHint, unsigned int listSz,
                const word32 *sizeList, const word32 *distList,
                unsigned char* buf, unsigned int sz, int flag, int max);

/*!
    \ingroup Memory

    \brief この関数は、NULLヒープヒントがメモリ割り当て関数に渡されたときに使用されるグローバルヒープヒントを設定します。これにより、アプリケーション全体で使用されるデフォルトのヒープヒントを設定できます。

    \return 設定されていた以前のグローバルヒープヒントを返します。

    \param hint グローバルヒープヒントとして使用するWOLFSSL_HEAP_HINT構造体。

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    WOLFSSL_HEAP_HINT* prev_hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    ...

    // 使用するメモリをロード
    ret = wc_LoadStaticMemory(&hint, memory, memorySz, WOLFMEM_GENERAL, 0);
    if (ret != SSL_SUCCESS) {
        // エラーケースを処理
    }

    // グローバルヒープヒントとして設定
    prev_hint = wolfSSL_SetGlobalHeapHint(&hint);
    if (prev_hint != NULL) {
        // 以前のグローバルヒープヒントがありました
    }
    \endcode

    \sa wolfSSL_GetGlobalHeapHint
    \sa wc_LoadStaticMemory
*/
WOLFSSL_HEAP_HINT* wolfSSL_SetGlobalHeapHint(WOLFSSL_HEAP_HINT* hint);

/*!
    \ingroup Memory

    \brief この関数は、NULLヒープヒントがメモリ割り当て関数に渡されたときに使用される現在のグローバルヒープヒントを取得します。

    \return 現在のグローバルヒープヒントを返します。設定されていない場合はNULLを返します。

    \param none パラメータなし。

    _Example_
    \code
    WOLFSSL_HEAP_HINT* current_hint;
    ...

    current_hint = wolfSSL_GetGlobalHeapHint();
    if (current_hint != NULL) {
        // グローバルヒープヒントが設定されています
        // current_hintを操作に使用できます
    }
    \endcode

    \sa wolfSSL_SetGlobalHeapHint
    \sa wc_LoadStaticMemory
*/
WOLFSSL_HEAP_HINT* wolfSSL_GetGlobalHeapHint(void);

/*!
    \ingroup Memory

    \brief この関数は、静的メモリ割り当て追跡用のデバッグコールバック関数を設定します。WOLFSSL_STATIC_MEMORY_DEBUG_CALLBACKビルドオプションと共に使用されます。コールバック関数は、メモリ割り当ておよび割り当て解除操作中に呼び出され、デバッグ情報を提供します。

    \return 成功した場合、0が返されます。
    \return すべての失敗した戻り値は0未満になります。

    \param cb 設定するデバッグコールバック関数。

    _Example_
    \code
    static void debug_memory_cb(const char* func, const char* file, int line,
                                void* ptr, size_t size, int type)
    {
        printf("Memory %s: %s:%d ptr=%p size=%zu type=%d\n",
               func, file, line, ptr, size, type);
    }
    ...

    // デバッグコールバックを設定
    int ret = wolfSSL_SetDebugMemoryCb(debug_memory_cb);
    if (ret != 0) {
        // エラーケースを処理
    }
    \endcode

    \sa none
*/
void wolfSSL_SetDebugMemoryCb(DebugMemoryCb cb);

/*!
    \ingroup Memory

    \brief この関数は、静的メモリヒープと関連するミューテックスを解放します。静的メモリ割り当ての使用が完了したときに、リソースを適切にクリーンアップするために呼び出す必要があります。

    \return 成功した場合、0が返されます。
    \return すべての失敗した戻り値は0未満になります。

    \param hint アンロードするWOLFSSL_HEAP_HINT構造体。

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    ...

    // 使用するメモリをロード
    ret = wc_LoadStaticMemory(&hint, memory, memorySz, WOLFMEM_GENERAL, 0);
    if (ret != SSL_SUCCESS) {
        // エラーケースを処理
    }

    // 操作にメモリを使用
    ...

    // 完了時にクリーンアップ
    wc_UnloadStaticMemory(&hint);
    \endcode

    \sa wc_LoadStaticMemory
    \sa wc_LoadStaticMemory_ex
*/
void wc_UnloadStaticMemory(WOLFSSL_HEAP_HINT* heap);

/*!
    \ingroup Memory

    \brief この関数は、カスタムバケットサイズと配分を使用した静的メモリ割り当てに必要なバッファサイズを計算します。この拡張バージョンでは、デフォルトの事前定義されたサイズを使用する代わりに、カスタムバケットサイズを使用できます。

    \return バッファサイズの計算が正常に完了すると、正の値が返されます。
    \return すべての負の値はエラーケースと見なされます。

    \param bucket_sizes 使用するバケットサイズの配列。
    \param bucket_count 配列内のバケットサイズの数。
    \param flag 希望するメモリタイプ、つまりWOLFMEM_GENERALまたはWOLFMEM_IO_POOL。

    _Example_
    \code
    word32 sizeList[] = {64, 128, 256, 512, 1024};
    word32 distList[] = {1, 2, 1, 1, 1};
    int listSz = 5;
    int optimum;

    optimum = wolfSSL_StaticBufferSz_ex(listSz, sizeList, distList, NULL, 0,
        WOLFMEM_GENERAL);
    if (optimum < 0) { //エラーケースを処理 }
    printf("カスタムバケットでの最適なバッファサイズは %d です\n", optimum);
    ...
    \endcode

    \sa wolfSSL_StaticBufferSz
    \sa wc_LoadStaticMemory_ex
*/
int wolfSSL_StaticBufferSz_ex(unsigned int listSz,
            const word32 *sizeList, const word32 *distList,
            byte* buffer, word32 sz, int flag);
