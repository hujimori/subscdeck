# テストデータ自動投入ガイド

## 概要
開発環境でサーバーを起動するたびに、自動的にテストデータが投入される機能です。

## 設定方法

### 1. testユーザーでサインアップ
まず、通常通りアプリケーションでユーザー名 `test` でサインアップしてください。

### 2. testユーザーのIDを確認
サインアップ後、Cognitoが生成したユーザーIDを確認します。以下のいずれかの方法で確認できます：

#### 方法A: ダッシュボードのネットワークタブから確認
1. testユーザーでログイン
2. ブラウザの開発者ツールを開く
3. ネットワークタブで `/api/subscriptions` のレスポンスを確認
4. `user_id` フィールドの値をコピー

#### 方法B: データベースから確認
```bash
sqlite3 subscdeck.db
sqlite> SELECT DISTINCT user_id FROM subscriptions;
```

### 3. 環境変数の設定
```bash
# 開発環境モード
export APP_ENV=development

# testユーザーのID（例：Cognitoが生成したUUID）
export TEST_USER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# その他の必要な環境変数
export AWS_PROFILE=subscdeck-dev
```

### 4. サーバー起動
```bash
go run main.go
```

## 動作確認

サーバー起動時に以下のようなログが表示されれば成功です：

```
Running seed data for development environment...
Starting seed data for test user: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Created subscription: Spotify (ID: 1)
Created subscription: Netflix (ID: 2)
Created 22 usage logs for subscription ID 1 in 2025-07
Created 18 usage logs for subscription ID 1 in 2025-06
Created 20 usage logs for subscription ID 1 in 2025-05
Created 13 usage logs for subscription ID 2 in 2025-07
Created 11 usage logs for subscription ID 2 in 2025-06
Created 12 usage logs for subscription ID 2 in 2025-05
Successfully seeded test data for user: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Test data seeded successfully
```

## テストデータの内容

### サブスクリプション
- **Spotify**: 月額980円
- **Netflix**: 月額1,490円

### 利用履歴パターン
- **Spotify**: 月平均20回利用（±30%の変動）
- **Netflix**: 月平均12回利用（±30%の変動）
- **曜日分布**: 金曜日・土曜日に利用が多くなる傾向

### データのリセット
サーバーを再起動するたびに、testユーザーの既存データは削除され、新しいランダムデータが生成されます。

## 注意事項

- `APP_ENV=development` が設定されていない場合、テストデータは投入されません
- `TEST_USER_ID` が設定されていない場合、データベースから最新のユーザーIDを探しますが、確実ではありません
- 本番環境では絶対に `APP_ENV=development` を設定しないでください