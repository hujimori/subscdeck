# CLAUDE.md

このファイルは、Claude Code (claude.ai/code) がこのリポジトリのコードを扱う際の指針を提供します。

## プロジェクト概要

subscdeckは、Go言語とEcho v4フレームワークを使用したWebアプリケーションです。サブスクリプションサービスの利用状況を記録・可視化することを目的としています。認証基盤にはAWS Cognitoを利用しています。

## 技術スタック

- **言語**: Go 1.22.4
- **Webフレームワーク**: Echo v4
- **データベース**: SQLite
- **認証**: AWS Cognito (JWTとJWKSによる検証)
- **AWS SDK**: AWS SDK for Go v2
- **設定管理**: godotenv (環境変数 or .envファイル)

## 主なコマンド

```bash
# 依存関係をインストール
go mod tidy

# 開発用サーバーを起動
go run main.go

# 開発用のテストデータを投入（データベースをリセット）
go run cmd/seeder/main.go

# アプリケーションをビルド
go build -o subscdeck main.go

# 環境変数を直接指定して実行する場合の例
AWS_PROFILE=subscdeck-dev go run main.go
```

## アーキテクチャ

アプリケーションは `internal` ディレクトリ以下に主要なロジックが集約されています。

- `internal/database`: データベースの初期化、接続、およびデータ操作（CRUD）を担当します。
- `internal/handler`: HTTPリクエストを受け取り、レスポンスを返すハンドラ関数を定義します。
- `internal/middleware`: 認証処理など、HTTPリクエストに対するミドルウェアを定義します。
- `internal/model`: アプリケーションで利用するデータ構造（モデル）を定義します。
- `internal/seeder`: 開発用のテストデータを生成するためのロジックを担当します。

## 主要な実装詳細

- **認証**: ユーザーのサインアップ、ログイン処理はAWS Cognito SDKを利用して行われます。APIへのアクセス制御は、Cognitoが発行するJWT（アクセストークン）を検証するカスタムミドルウェア (`internal/middleware/auth.go`) によって実現されています。
- **公開鍵の取得**: JWTの署名検証に使用する公開鍵は、CognitoのJWKSエンドポイントから取得します。
- **設定**: AWSの認証情報やCognitoのプールIDといった設定値は、`.env.local` または `.env` ファイルから読み込まれます。これらのファイルが存在しない場合は、環境変数が利用されます。
