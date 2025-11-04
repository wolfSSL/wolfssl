/*!
    \ingroup Memory

    \brief これは実際には関数ではなく、プリプロセッサマクロです。
    ユーザーが標準のCメモリ関数の代わりに独自のmalloc、realloc、free関数を置き換えることを可能にします。
    外部メモリ関数を使用するには、XMALLOC_USERを定義します。これにより、メモリ関数は次の形式の外部関数に置き換えられます:
    extern void *XMALLOC(size_t n, void* heap, int type);
    extern void *XREALLOC(void *p, size_t n, void* heap, int type);
    extern void XFREE(void *p, void* heap, int type);
    wolfSSL_Malloc、wolfSSL_Realloc、wolfSSL_Freeの代わりに基本的なCメモリ関数を使用するには、NO_WOLFSSL_MEMORYを定義します。
    これにより、メモリ関数は次のように置き換えられます:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) free((xp));}
    #define XREALLOC(p, n, h, t) realloc((p), (n))
    これらのオプションのいずれも選択されていない場合、システムはデフォルトでwolfSSLメモリ関数を使用します。
    ユーザーはコールバックフックを通じてカスタムメモリ関数を設定できます(wolfSSL_Malloc、wolfSSL_Realloc、wolfSSL_Freeを参照)。
    このオプションは、メモリ関数を次のように置き換えます:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, wolfSSL_Malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) wolfSSL_Free((xp));}
    #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n))

    \return pointer 成功時に割り当てられたメモリへのポインタを返します
	\return NULL 失敗時

	\param s 割り当てるメモリのサイズ
	\param h (カスタムXMALLOC関数で使用)使用するヒープへのポインタ
	\param t ユーザーヒント用のメモリ割り当てタイプ。types.hの列挙型を参照

	_Example_
	\code
	int* tenInts = XMALLOC(sizeof(int)*10, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tenInts == NULL) {
	    // スペース割り当てエラー
	    return MEMORY_E;
    }
	\endcode

	\sa wolfSSL_Malloc
	\sa wolfSSL_Realloc
	\sa wolfSSL_Free
	\sa wolfSSL_SetAllocators
*/
void* XMALLOC(size_t n, void* heap, int type);

/*!
    \ingroup Memory

    \brief これは実際には関数ではなく、プリプロセッサマクロです。
    ユーザーが標準のCメモリ関数の代わりに独自のmalloc、realloc、free関数を置き換えることを可能にします。
    外部メモリ関数を使用するには、XMALLOC_USERを定義します。これにより、メモリ関数は次の形式の外部関数に置き換えられます:
    extern void *XMALLOC(size_t n, void* heap, int type);
    extern void *XREALLOC(void *p, size_t n, void* heap, int type);
    extern void XFREE(void *p, void* heap, int type);
    wolfSSL_Malloc、wolfSSL_Realloc、wolfSSL_Freeの代わりに基本的なCメモリ関数を使用するには、NO_WOLFSSL_MEMORYを定義します。
    これにより、メモリ関数は次のように置き換えられます:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, malloc((s)))
   	#define XFREE(p, h, t)   	{void* xp = (p); if((xp)) free((xp));}
   	#define XREALLOC(p, n, h, t) realloc((p), (n))
    これらのオプションのいずれも選択されていない場合、システムはデフォルトでwolfSSLメモリ関数を使用します。
    ユーザーはコールバックフックを通じてカスタムメモリ関数を設定できます(wolfSSL_Malloc、wolfSSL_Realloc、wolfSSL_Freeを参照)。
    このオプションは、メモリ関数を次のように置き換えます:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, wolfSSL_Malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) wolfSSL_Free((xp));}
    #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n))

    \return 成功時に割り当てられたメモリへのポインタを返します
	\return NULL 失敗時

	\param p 再割り当てするアドレスへのポインタ
	\param n 割り当てるメモリのサイズ
	\param h (カスタムXREALLOC関数で使用)使用するヒープへのポインタ
	\param t ユーザーヒント用のメモリ割り当てタイプ。types.hの列挙型を参照

	_Example_
	\code
	int* tenInts = (int*)XMALLOC(sizeof(int)*10, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    int* twentyInts = (int*)XREALLOC(tenInts, sizeof(int)*20, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
	\endcode

	\sa wolfSSL_Malloc
	\sa wolfSSL_Realloc
	\sa wolfSSL_Free
	\sa wolfSSL_SetAllocators
*/
void* XREALLOC(void *p, size_t n, void* heap, int type);

/*!
    \ingroup Memory

    \brief これは実際には関数ではなく、プリプロセッサマクロです。
    ユーザーが標準のCメモリ関数の代わりに独自のmalloc、realloc、free関数を置き換えることを可能にします。
    外部メモリ関数を使用するには、XMALLOC_USERを定義します。
    これにより、メモリ関数は次の形式の外部関数に置き換えられます:
    extern void *XMALLOC(size_t n, void* heap, int type);
    extern void *XREALLOC(void *p, size_t n, void* heap, int type);
    extern void XFREE(void *p, void* heap, int type);
    wolfSSL_Malloc、wolfSSL_Realloc、wolfSSL_Freeの代わりに基本的なCメモリ関数を使用するには、NO_WOLFSSL_MEMORYを定義します。
    これにより、メモリ関数は次のように置き換えられます:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) free((xp));}
    #define XREALLOC(p, n, h, t) realloc((p), (n))
    これらのオプションのいずれも選択されていない場合、システムはデフォルトでwolfSSLメモリ関数を使用します。
    ユーザーはコールバックフックを通じてカスタムメモリ関数を設定できます(wolfSSL_Malloc、wolfSSL_Realloc、wolfSSL_Freeを参照)。
    このオプションは、メモリ関数を次のように置き換えます:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, wolfSSL_Malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) wolfSSL_Free((xp));}
    #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n))

    \return none 戻り値なし。

    \param p 解放するアドレスへのポインタ
	\param h (カスタムXFREE関数で使用)使用するヒープへのポインタ
	\param t ユーザーヒント用のメモリ割り当てタイプ。types.hの列挙型を参照

	_Example_
	\code
	int* tenInts = XMALLOC(sizeof(int) * 10, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tenInts == NULL) {
	    // スペース割り当てエラー
	    return MEMORY_E;
    }
	\endcode

	\sa wolfSSL_Malloc
	\sa wolfSSL_Realloc
	\sa wolfSSL_Free
	\sa wolfSSL_SetAllocators
*/
void XFREE(void *p, void* heap, int type);

/*!
    \ingroup Math

    \brief この関数は、コンパイル時のクラス設定をチェックします。
    ユーザーがwolfCryptライブラリを独立して使用している場合に重要です。
    数学が正しく動作するためには、ライブラリ間で設定が一致している必要があります。
    このチェックはCheckCtcSettings()として定義されており、CheckRunTimeSettingsとCTC_SETTINGSを単純に比較し、不一致の場合は0を、一致する場合は1を返します。

    \return settings ランタイムCTC_SETTINGS(コンパイル時設定)を返します

    \param none パラメータなし。

    _Example_
    \code
    if (CheckCtcSettings() != 1) {
	    return err_sys("Build vs. runtime math mismatch\n");
    }
    // これはプリプロセッサによって次のように変換されます:
    // if ( (CheckCtcSettings() == CTC_SETTINGS) != 1) {
    // そしてコンパイル時のクラス設定が現在の設定と一致するかどうかを比較します
    \endcode

    \sa CheckRunTimeFastMath
*/
word32 CheckRunTimeSettings(void);