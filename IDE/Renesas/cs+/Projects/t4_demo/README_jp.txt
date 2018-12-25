wolfSSL/AlphaProjectボードデモ　セットアップガイド

このデモはRenesas CS+ v6.01、AP-RX71M-0A, wolfSSL 3.15.3 でテストしています。

セットアップ手順：

１．ソフトウェアの入手
　- APボード付属のソフトウェア一式を適当なフォルダー下に解凍します。
　- 同じフォルダー下にwolfssl一式を解凍します。

２．wolfSSLのセットアップ
　- CS+にてwolfssl\IDE\Renesas\cs+\Project下のwolfssl\lib.mtpjを開き
　　wolfSSLライブラリーのビルドをします。
　- 同じフォルダの下のt4_demo.mtpjを開き、デモプログラムのビルドをします。
　このプログラムもライブラリー形式でビルドされます。
　
３．AlphaProject側のセットアップ
　デモはap_rx71m_0a_sample_cs\Sample\ap_rx71m_0a_ether_sample_csフォルダ下の
　ap_rx71m_0a_ether_sample_cs.mtpjプロジェクトを利用します。
　
　- ap_rx71m_0a_sample_cs\Sample\ap_rx71m_0a_ether_sample_cs\srcフォルダ下の
　AP_RX71M_0A.cファイルを開き、
　９７行目のecho_srv_init()の下にwolfSSL_init()を挿入します。

===
	sci_init();
	can_init();
	echo_srv_init();
	wolfSSL_init(); <- この行を挿入
===

　- ap_rx71m_0a_sample_cs\Sample\ap_rx71m_0a_ether_sample_cs\src\r_configファイル
　を開き、スタックサイズとヒープサイズを以下のように設定します。
　
　120行目 #pragma stacksize su=0x2000
　139行目 #define BSP_CFG_HEAP_BYTES  (0xa000)

　- IPアドレスのデフォルト値は以下のようになっています。
　必要があれば、Sample\ap_rx71m_0a_ether_sample_cs\src\r_t4_rx\src\config_tcpudp.c
　内の139行目からの定義を変更します。
　
===
#define MY_IP_ADDR0     192,168,1,200           /* Local IP address  */
#define GATEWAY_ADDR0   192,168,1,254           /* Gateway address (invalid if all 0s) */
#define SUBNET_MASK0    255,255,255,0           /* Subnet mask  */
===

　- CS+でap_rx71m_0a_ether_sample_cs.mtpjプロジェクトを開き、wolfSSLとデモライブラリを
　登録します。CC-RX(ビルドツール)->リンク・オプションタブ->使用する以下の二つのファイル
　を登録します。
　wolfssl\IDE\Renesas\cs+\Projects\wolfssl_lib\DefaultBuild\wolfssl_lib.lib
　wolfssl\IDE\Renesas\cs+\Projects\t4_demo\DefaultBuild\t4_demo.lib

- CC-RX(ビルドツール)->ライブラリージェネレーションタブ->ライブラリー構成を「C99」に、
ctype.hを有効にするを「はい」に設定します。

　- プロジェクトのビルド、ターゲットへのダウンロードをしたのち、表示->デバッグ・コンソール
　からコンソールを表示させます。実行を開始するとコンソールに以下の表示が出力されます。
　
===
　wolfSSL Demo
t: test, b: benchmark, s: server, or c <IP addr> <Port>: client
$
===

tコマンド：各暗号化アルゴリズムの簡単なテストを実行します。所要のアルゴリズムが
　組み込まれているか確認することができます。組み込むアルゴリズムはビルドオプション
　で変更することができます。詳しくはユーザマニュアルを参照してください。
bコマンド：各暗号アルゴリズムごとの簡単なベンチマークを実行します。
sコマンド：簡単なTLSサーバを起動します。起動するとビルド時のIPアドレス、
　ポート50000にてTLS接続を待ちます。
cコマンド：簡単なTLSクライアントを起動します。起動すると第一アーギュメントで指定された
　IPアドレス、第二アーギュメントで指定されたポートに対してTLS接続します。

いずれのコマンドも１回のみ実行します。繰り返し実行したい場合は、MPUをリセットして
再起動します。

４．対向テスト
　デモのｓ、ｃコマンドを使って、他の機器と簡単な対向テストをすることができます。
　UbuntuなどのGCC, make環境、WindowsのVisual Studioなどで
　対向テスト用のサーバ、クライアントをビルドすることができます。

　GCC,makeコマンド環境では、ダウンロード解凍したwolfsslのディレクトリ下で以下の
　コマンドを発行すると、ライブラリ、テスト用のクライアント、サーバなど一式がビルド
　されます。
　
　$ ./configure
　$ make check
　
　その後、以下のような指定でクライアントまたはサーバを起動して、ボード上の
　デモと対向テストすることができます。
　
　PC側：
　$ ./examples/server/server -b -d
　ボード側：
　　> c <IPアドレス> 11111

　ボード側：
　　> s
　PC側：　
　$ ./examples/client/client -h <IPアドレス> -p 50000
　
　
　WindowsのVisual Studioでは、ダウンロード解凍したwolfsslフォルダ下のwolfssl64.sln
　を開き、ソリューションをビルドします。Debugフォルダ下にビルドされるclient.exeと
　server.exeを利用します。
　
  PC側：
　Debug> .\server -b -d
　ボード側：
　　> c <IPアドレス> 11111

　ボード側：
　　> s
　PC側：
　Debug> .\client  -h <IPアドレス> -p 50000

以上、