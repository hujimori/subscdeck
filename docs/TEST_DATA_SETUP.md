# 開発用テストデータ投入ガイド

## 概要

開発環境で利用するテストデータをデータベースに投入するためのガイドです。

この処理は、特定のテストユーザー (`test001`) に対して、既存のデータを一度すべて削除した上で、新しいサンプルデータを再生成します。

## テストユーザー情報

- **Username**: `test001`
- **User ID**: `77448a08-9001-70cf-ba00-98f2b665608b`

## データ投入コマンド

以下のコマンドを実行すると、データベース (`subscdeck.db`) にテストデータが投入されます。

```bash
go run cmd/seeder/main.go
```

### 実行前の注意

コマンドを実行する前に、必要な環境変数が設定されていることを確認してください。通常、`.env.local` または `.env` ファイルに記述されています。

- `AWS_REGION`
- `COGNITO_USER_POOL_ID`
- `COGNITO_CLIENT_ID`

## 投入されるデータの内容

- **サブスクリプション**: 
  - Spotify (月額980円)
  - Netflix (月額1490円)
- **利用履歴**:
  - 上記の各サブスクリプションに対して、過去12ヶ月分のランダムな利用履歴が生成されます。
  - 利用頻度はサービスごとに異なり、週末に利用が多くなる傾向があります。

## 実行ログの例

コマンドが成功すると、以下のようなログが出力されます。

```
Starting seed data for test user: 77448a08-9001-70cf-ba00-98f2b665608b
Created subscription: Spotify (ID: 1)
Created subscription: Netflix (ID: 2)
Created 22 usage logs for subscription ID 1 in 2025-07
Created 18 usage logs for subscription ID 1 in 2025-06
...
Created 13 usage logs for subscription ID 2 in 2025-07
Created 11 usage logs for subscription ID 2 in 2025-06
...
Successfully seeded test data for user: 77448a08-9001-70cf-ba00-98f2b665608b
Database seeding completed successfully.
```

## 注意事項

- このコマンドは、`main.go` を起動するWebサーバーとは独立して実行します。
- サーバー起動時に自動でデータが投入されることはなくなりました。
- データをリセットしたい場合は、再度このコマンドを実行してください。
