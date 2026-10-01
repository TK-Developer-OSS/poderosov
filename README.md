# PoderosoV

SSH ターミナル Poderosa 4.x の操作感を、Rust + Tauri で作り直すプロジェクトです。
fork ではなく再実装で、Windows / macOS / Linux で動くことを目指します。

## 現状

- SSH2 接続（パスワード認証、公開鍵認証）
- ホスト鍵の確認と登録
- タブ付きのターミナル（xterm.js）、コピー (Alt+C)、貼り付け (Alt+V)
- パスワード・パスフレーズの一時記憶（アプリ終了まで。メモリ上のみ）
- オプション: フォント、フォントサイズ（既定 10.5pt）、既定のエンコーディング
- エンコーディング: UTF-8（既定）、EUC-JP、Shift_JIS
- XMODEM 送信（128 バイトブロック、CRC / チェックサム）

## 残タスク

- オプション: エージェントフォワーディング
- COM ポート（シリアル）接続
- 鍵ファイルの生成
- ポートフォワーディング
- ログ設定とログ保存
- XMODEM 受信

## 構成

| 場所 | 内容 |
| --- | --- |
| `crates/poderosov-core` | 接続とセッション。GUI に依存しない |
| `src-tauri` | Tauri アプリ本体。core とウィンドウの橋渡し |
| `ui` | 画面（HTML / CSS / JavaScript）。ビルド時にバイナリへ埋め込まれる |

## ビルドと実行

Rust 1.89 以降と C コンパイラが必要です。Node.js は不要です。

```sh
cargo run -p poderosov     # 起動
cargo test                 # テスト（テスト用の SSH サーバーをプロセス内で動かす）
```

Windows では WebView2 ランタイムが、Linux では WebKitGTK の開発パッケージが必要です。

## 同梱している第三者のコード

`ui/vendor/xterm` は [xterm.js](https://github.com/xtermjs/xterm.js) の配布物です
（`@xterm/xterm` 6.0.0、`@xterm/addon-fit` 0.11.0、MIT ライセンス）。
