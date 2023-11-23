# websocket-rs

以下の記事の写経です:
- https://zenn.dev/ohke/articles/8d6b690c144a0e

WebSocketクライアントから送信されたテキストをechoするWebSocketサーバーの簡易実装。

対応しているOpcodeは以下です:
- Text
- Close

詳細はこちらを参照:
- https://www.rfc-editor.org/rfc/rfc6455

## 手順
1. `cargo run`
1. WebSocketのクライアントから`ws://127.0.0.1:7778/`につなぐ(handshake using HTTP)
1. クライアントから`Text` を送信する
   - 任意の文字列を送信すると、3秒後にechoされる
1. クライアントから`Close`を送信する
