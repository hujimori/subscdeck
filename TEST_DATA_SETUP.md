# テストデータ自動投入ガイド

## 概要
開発環境でサーバーを起動するたびに、自動的にtest001ユーザー用のテストデータが投入される機能です。

## 設定済みのテストユーザー

**Username**: `test001`  
**User ID**: `77448a08-9001-70cf-ba00-98f2b665608b`

## 設定方法

### 環境変数の設定
```bash
# 開発環境モード
export APP_ENV=development

# その他の必要な環境変数
export AWS_PROFILE=subscdeck-dev
```

**注意**: ユーザーIDはコードに直接組み込まれているため、`TEST_USER_ID`環境変数の設定は不要です。

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