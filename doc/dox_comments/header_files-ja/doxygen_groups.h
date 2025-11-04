/*!
    \defgroup 3DES アルゴリズム - 3DES
    \defgroup AES アルゴリズム - AES
    \defgroup ARC4 アルゴリズム - ARC4
    \defgroup BLAKE2 アルゴリズム - BLAKE2
    \defgroup Camellia アルゴリズム - Camellia
    \defgroup ChaCha アルゴリズム - ChaCha
    \defgroup ChaCha20Poly1305 アルゴリズム - ChaCha20_Poly1305
    \defgroup CMAC アルゴリズム - CMAC
    \defgroup Crypto Callbacksコールバック - CryptoCb
    \defgroup Curve25519 アルゴリズム - Curve25519
    \defgroup Curve448 アルゴリズム - Curve448
    \defgroup DSA アルゴリズム - DSA
    \defgroup Diffie-Hellman アルゴリズム - Diffie-Hellman
    \defgroup ECC アルゴリズム - ECC
    \defgroup ED25519 アルゴリズム - ED25519
    \defgroup ED448 アルゴリズム - ED448
    \defgroup ECCSI_Overview ECC​​SIの概要
    ECCSI(楕円曲線ベースの証明書レス署名によるアイデンティティベース暗号化)は、RFC 6507(https://tools.ietf.org/html/rfc6507)で規定されています。

    アイデンティティベース暗号化では、クライアントのアイデンティティに基づいてキーを生成する鍵管理サービスがあります。
    秘密鍵(SSK)と公開鍵(PVT)は署名者に配信され、公開鍵(PVT)のみがリクエストに応じて検証者に配信されます。\n\n
    wolfCryptは次の機能を提供します:
      -# KMS鍵の作成
      -# 署名鍵ペアの生成
      -# 署名鍵ペアの検証
      -# メッセージの署名
      -# メッセージの検証

    KMS:
      -# ECCSI鍵の初期化: wc_InitEccsiKey()
      -# ECCSI鍵の作成と保存またはロード:
        -# wc_MakeEccsiKey(), wc_ExportEccsiKey(), wc_ExportEccsiPublicKey() または
        -# wc_ImportEccsiKey()
      -# リクエストを待機:
        -# クライアントから署名IDを受信
        -# IDから署名鍵ペアを生成: wc_MakeEccsiPair()
        -# 結果をエンコード:
          -# 署名者用に署名鍵ペア: wc_EncodeEccsiPair()
        -# KPAKと結果を送信
      -# ECCSI鍵の解放: wc_FreeEccsiKey()

    クライアント、署名者:
      -# ECCSI鍵の初期化: wc_InitEccsiKey()
      -# (署名ペアがキャッシュされていない場合)KMSにKPAKと署名ペアをリクエスト
        -# KMSに署名IDを送信
        -# KMSから署名鍵ペアを受信
        -# KMS公開鍵をロード: wc_ImportEccsiPublicKey()
        -# 署名鍵ペアをデコード: wc_DecodeEccsiPair()
        -# 鍵ペアを検証: wc_ValidateEccsiPair()
      -# (上記で実行していない場合)KMS公開鍵をロード: wc_ImportEccsiPublicKey()
      -# (キャッシュされていない場合)IDとPVTのハッシュを計算: wc_HashEccsiId()
      -# 各メッセージに対して:
        -# アイデンティティのハッシュを設定: wc_SetEccsiHash()
        -# メッセージに署名: wc_SignEccsiHash()
        -# ハッシュID、メッセージ、署名をピアに送信
      -# ECCSI鍵の解放: wc_FreeEccsiKey()

    クライアント、検証者:
      -# 署名者からハッシュID、メッセージ、署名を受信
      -# KMSにKPAK(キャッシュされていない場合)とハッシュIDのPVT(キャッシュされていない場合)をリクエスト
      -# KMSからKPAK(キャッシュされていない場合)とハッシュIDのPVT(キャッシュされていない場合)を受信
      -# ECCSI鍵の初期化: wc_InitEccsiKey()
      -# KMS公開鍵をロード: wc_ImportEccsiPublicKey()
      -# PVTをデコード: wc_DecodeEccsiPvtFromSig()
      -# IDとPVTのハッシュを計算: wc_HashEccsiId()
      -# ECCSI鍵ペアを設定: wc_SetEccsiPair()
      -# メッセージの署名を検証: wc_VerifyEccsiHash()
      -# ECCSI鍵の解放: wc_FreeEccsiKey()

    \defgroup ECCSI_Setup ECCSI鍵のセットアップ
    ECCSI鍵を確立するための操作。

    使用前にECCSI鍵を初期化(wc_InitEccsiKey())。\n
    P256以外の曲線を使用する場合は、使用前にECCSI鍵を初期化(wc_InitEccsiKey_ex())。\n
    新しい鍵を作成(wc_MakeEccsiKey())、既存の鍵をインポート(wc_ImportEccsiKey())、または既存の秘密鍵(wc_ImportEccsiPrivateKey())と公開鍵(wc_ImportEccsiPublicKey())をインポート。\n
    新しい鍵を作成した後、将来の使用のために鍵をエクスポート(wc_ExportEccsiKey())。\n
    新しい鍵を作成した後、将来の使用のために秘密鍵をエクスポート(wc_ExportEccsiPrivateKey())。\n
    KMSからクライアントに渡すために公開鍵をエクスポート(wc_ExportEccsiPublicKey())。\n
    クライアントに公開鍵をインポート(wc_ImportEccsiPublicKey())。\n
    終了時にECCSI鍵を解放(wc_FreeEccsiKey())。

    \defgroup ECCSI_Operations ECCSI鍵での署名と検証のための操作
    これらは、ECCSI鍵を使用した署名と検証のための操作です。

    署名時に使用する署名者のIDでECCSI鍵ペアを作成(wc_MakeEccsiPair())。\n
    署名者のIDでECCSI鍵ペアを検証(wc_ValidateEccsiPair())。\n
    ECCSI公開検証トークン(PVT)を検証(wc_ValidateEccsiPvt())。\n
    クライアントへの転送のためにECCSI鍵ペアをエンコード(wc_EncodeEccsiPair())。\n
    クライアントへの転送のためにECCSI SSKをエンコード(wc_EncodeEccsiSsk())。\n
    検証者への転送のためにECCSI PVTをエンコード(wc_EncodeEccsiPvt())。\n
    署名のためにクライアントでECCSI鍵ペアをデコード(wc_DecodeEccsiPair())。\n
    署名のためにクライアントでECCSI SSKをデコード(wc_DecodeEccsiSsk())。\n
    署名のためにクライアントでECCSI PVTをデコード(wc_DecodeEccsiPvt())。\n
    検証のためにクライアントで署名からECCSI PVTをデコード(wc_DecodeEccsiPvtFromSig())。\n
    IDと公開検証トークン(PVT)を使用した署名/検証のためにIDのハッシュを計算(wc_HashEccsiId())。\n
    IDのハッシュと秘密署名鍵(SSK)および公開検証トークン(PVT)でメッセージに署名(wc_SignEccsiHash())。\n
    署名者のIDのハッシュでメッセージを検証(wc_VerifyEccsiHash())。

    \defgroup SAKKE_Overview SAKKE鍵の概要
    SAKKE(酒井-笠原鍵暗号化)は、RFC 6508(https://tools.ietf.org/html/rfc6508)で規定されています。

    SAKKEは、アイデンティティベース暗号化を使用してピアに秘密を転送するために使用されます。\n
    鍵管理サービス(KMS)は、受信者秘密%鍵(RSK)の発行を担当します。
    最大(2^hashlen)^hashlenバイトのデータを転送できます。\n
    送信者は受信者のアイデンティティとKMS公開鍵を知っている必要があります。\n
    受信者は、秘密を導出するために、KMSからアイデンティティの受信者秘密鍵(RSK)を取得している必要があります。

    KMS:
      -# SAKKE鍵の初期化: wc_InitSakkeKey()
      -# SAKKE鍵の作成と保存またはロード:
        -# wc_MakeSakkeKey(), wc_ExportSakkeKey(), wc_ExportSakkePublicKey() または
        -# wc_ImportSakkeKey()
      -# リクエストを待機:
        -# クライアントのIDに基づいてRSKを作成: wc_MakeSakkeRsk()
        -# クライアントへの転送のためにRSKをエンコード: wc_EncodeSakkeRsk()
      -# SAKKE鍵の解放: wc_FreeSakkeKey()

    鍵交換、ピアA:
      -# SAKKE鍵の初期化: wc_InitSakkeKey()
      -# KMS公開鍵をロード: wc_ImportSakkePublicKey()
      -# ランダムなSSVを生成: wc_GenerateSakkeSSV()
      -# ピアBのアイデンティティを設定: wc_SetSakkeIdentity()
      -# カプセル化されたSSVと認証データを作成: wc_MakeSakkeEncapsulatedSSV()
      -# カプセル化されたデータをピアBに送信
      -# SAKKE鍵の解放: wc_FreeSakkeKey()

    鍵交換、ピアB:
      -# カプセル化されたデータを受信
      -# SAKKE鍵の初期化: wc_InitSakkeKey()
      -# KMS公開鍵をロード: wc_ImportSakkePublicKey()
      -# KMSから転送されたまたはローカルに保存されたRSKをデコード: wc_DecodeSakkeRsk()
      -# [オプション]最初の使用前にRSKを検証: wc_ValidateSakkeRsk()
      -# アイデンティティを設定: wc_SetSakkeIdentity()
      -# RSKと、オプションで事前計算テーブルを設定: wc_SetSakkeRsk()
      -# 認証データでSSVを導出: wc_DeriveSakkeSSV()
      -# SAKKE鍵の解放: wc_FreeSakkeKey()

    秘密の転送、ピアA:
      -# SAKKE鍵の初期化: wc_InitSakkeKey()
      -# KMS公開鍵をロード: wc_ImportSakkePublicKey()
      -# ピアBのアイデンティティを設定: wc_SetSakkeIdentity()
      -# SSVと認証データのカプセル化を作成: wc_MakeSakkeEncapsulatedSSV()
      -# カプセル化されたデータをピアBに送信
      -# SAKKE鍵の解放: wc_FreeSakkeKey()

    秘密の転送、ピアB:
      -# SAKKE鍵の初期化: wc_InitSakkeKey()
      -# KMS公開鍵をロード: wc_ImportSakkePublicKey()
      -# KMSから転送されたまたはローカルに保存されたRSKをデコード: wc_DecodeSakkeRsk()
      -# [オプション]最初の使用前にRSKを検証: wc_ValidateSakkeRsk()
      -# カプセル化されたデータを受信
      -# アイデンティティを設定: wc_SetSakkeIdentity()
      -# RSKと、オプションで事前計算テーブルを設定: wc_SetSakkeRsk()
      -# SSVと認証データを導出: wc_DeriveSakkeSSV()
      -# SAKKE鍵の解放: wc_FreeSakkeKey()

    \defgroup SAKKE_Setup SAKKE鍵のセットアップ
    SAKKE鍵を確立するための操作。

    使用前にSAKKE鍵を初期化(wc_InitSakkeKey()またはwc_InitSakkeKey_ex())。\n
    新しい鍵を作成(wc_MakeSakkeKey())または既存の鍵をインポート(wc_ImportSakkeKey())。\n
    新しい鍵を作成した後、将来の使用のために鍵をエクスポート(wc_ExportSakkeKey())。\n
    KMS SAKKE鍵の秘密部分のみが利用可能な場合、公開鍵を作成(wc_MakeSakkePublicKey())。\n
    ストレージからKMSから秘密鍵をエクスポート(wc_ExportSakkePrivateKey())。\n
    ストレージからKMSに秘密鍵をインポート(wc_ImportSakkePrivateKey())。\n
    KMSからクライアントに渡すために公開鍵をエクスポート(wc_ExportSakkePublicKey())。\n
    クライアントに公開鍵をインポート(wc_ImportSakkePublicKey())。\n
    クライアントに使用するアイデンティティを設定(wc_SetSakkeIdentity())。\n
    終了時にSAKKE鍵を解放(wc_FreeSakkeKey())。

    \defgroup SAKKE_RSK SAKKE RSKに関する/を使用した操作
    これらの操作は、受信者秘密鍵(RSK)を作成、検証、エンコード、デコードします。

    RSKは、SSVを導出するために必要です(wc_DeriveSakkeSSV()を参照)。\n
    KMSで、クライアントのIDからRSKを作成(wc_MakeSakkeRsk())。\n
    クライアントで、IDでRSKを検証(wc_ValidateSakkeRsk())。\n
    クライアントへの転送またはストレージのためにRSKをエンコード(wc_EncodeSakkeRsk())。\n
    必要に応じてクライアントでRSKをデコード(wc_DecodeSakkeRsk())。\n
    必要に応じてクライアントでRSKをインポート(wc_ImportSakkeRsk())。\n
    必要に応じてクライアントでRSKと、オプションで事前計算テーブルを設定(wc_SetSakkeRsk())。

    \defgroup SAKKE_Operations SAKKE鍵を使用した操作
    これらの操作は、共有秘密値(SSV)を1つのクライアントから別のクライアントに転送します。SSVはランダムに生成できます。

    認証データのサイズを計算(wc_GetSakkeAuthSize())して、バッファ内のSSVの開始位置を決定。\n
    中間点Iを作成(wc_MakeSakkePointI())して、カプセル化の作成とSSVの導出を高速化。\n
    ストレージのために中間点Iを取得(wc_GetSakkePointI())。\n
    ストレージから中間点Iを設定(wc_SetSakkePointI())。\n
    中間点Iの事前計算テーブルを生成(wc_GenerateSakkePointITable())してパフォーマンスをさらに向上。必要に応じて保存。\n
    中間点Iの事前計算テーブルを設定(wc_SetSakkePointITable())してパフォーマンスをさらに向上。\n
    中間点Iの事前計算テーブルをクリア(wc_ClearSakkePointITable())して外部テーブルポインタへの参照を削除。\n
    別のクライアントと共有するためにカプセル化されたSSVを作成(wc_MakeSakkeEncapsulatedSSV())。SSV内のデータが変更されます。\n
    鍵交換のためにランダムなSSVを生成(wc_GenerateSakkeSSV())。\n
    カプセル化されたSSVから受信者でSSVを導出(wc_DeriveSakkeSSV())。

    \defgroup HMAC アルゴリズム - HMAC
    \defgroup MD2 アルゴリズム - MD2
    \defgroup MD4 アルゴリズム - MD4
    \defgroup MD5 アルゴリズム - MD5
    \defgroup PKCS7 アルゴリズム - PKCS7
    \defgroup PKCS11 アルゴリズム - PKCS11
    \defgroup Password アルゴリズム - パスワードベース
    \defgroup Poly1305 アルゴリズム - Poly1305
    \defgroup RIPEMD アルゴリズム - RIPEMD
    \defgroup RSA アルゴリズム - RSA
    \defgroup SHA アルゴリズム - SHA 128/224/256/384/512
    \defgroup SipHash アルゴリズム - SipHash
    \defgroup SrtpKdf アルゴリズム - SRTP KDF
    \defgroup SRP アルゴリズム - SRP

    \defgroup ASN ASN.1
    \defgroup Base_Encoding ベースエンコーディング
    \defgroup CertManager 証明書マネージャーAPI
    \defgroup Compression 圧縮
    \defgroup Error エラー報告
    \defgroup IoTSafe IoT-Safeモジュール
    IoT-Safe(IoT-SIM Applet For Secure End-2-End Communication)は、SIMを堅牢で
    スケーラブルかつ標準化されたハードウェアRoot of Trustとして活用し、データ通信を保護する技術です。

    IoT-Safe SSLセッションは、SIMをハードウェアセキュリティモジュールとして使用し、すべての暗号公開
    鍵操作をオフロードし、証明書と鍵へのアクセスをSIMに制限することで攻撃対象領域を削減します。

    IoT-Safeサポートは、wolfSSL_CTX_iotsafe_enable()を使用して既存のWOLFSSL_CTXコンテキストで有効にできます。\n
    コンテキスト内で作成されたセッションは、IoT-Safe鍵とファイル使用のパラメータを設定し、
    wolfSSL_iotsafe_on()で公開鍵コールバックを有効にできます。

    コンパイルされている場合、モジュールはwolfCryptのエントロピーソースとしてIoT-Safe乱数生成器をサポートします。

    \defgroup PSA プラットフォームセキュリティアーキテクチャ(PSA)API
    \defgroup Keys 鍵と証明書の変換
    \defgroup Logging ロギング
    \defgroup Math 整数演算API
    \defgroup Memory メモリ処理
    \defgroup Random 乱数生成
    \defgroup Signature 署名API
    \defgroup openSSL OpenSSL API
    \defgroup wolfCrypt wolfCryptの初期化とクリーンアップ
    \defgroup TLS wolfSSLの初期化/シャットダウン
    \defgroup CertsKeys wolfSSL証明書と鍵
    \defgroup Setup wolfSSLコンテキストとセッションのセットアップ
    \defgroup IO wolfSSL接続、セッション、I/O
    \defgroup Debug wolfSSLエラー処理と報告
*/