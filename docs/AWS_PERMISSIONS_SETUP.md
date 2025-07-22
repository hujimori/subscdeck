# AWS Cognito ListUsers API 権限設定ガイド

## 概要
サインアップ時のメールアドレス重複チェック機能を有効にするには、アプリケーションがCognito User Poolの`ListUsers` APIを呼び出せるように権限を設定する必要があります。

## 現在の設定
`subscdeck-dev`プロファイルにListUsers APIの実行権限が付与されています。

## 実行方法

アプリケーションを起動する際は、AWS_PROFILE環境変数を設定してください：

```bash
# 環境変数を設定して実行
AWS_PROFILE=subscdeck-dev go run main.go

# または、環境変数をエクスポートしてから実行
export AWS_PROFILE=subscdeck-dev
go run main.go
```

## 解決方法

### オプション1: AWS IAMロールの使用（推奨）

1. **IAMロールの作成**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "cognito-idp:ListUsers"
         ],
         "Resource": "arn:aws:cognito-idp:ap-northeast-1:YOUR_ACCOUNT_ID:userpool/ap-northeast-1_QMNYJ3EiD"
       }
     ]
   }
   ```

2. **環境変数またはIAMロールをEC2/ECS/Lambda等に割り当て**

3. **AWS SDK v2の設定でIAMロールを使用**
   ```go
   cfg, err := config.LoadDefaultConfig(context.TODO(),
       config.WithRegion(region),
   )
   ```

### オプション2: AWS認証情報の設定

1. **IAMユーザーの作成と権限付与**
   - 上記と同じポリシーをIAMユーザーに付与

2. **環境変数の設定**
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_REGION=ap-northeast-1
   ```

### オプション3: Lambda関数による実装

1. **Lambda関数の作成**
   - ListUsers権限を持つLambda関数を作成
   - API Gateway経由で呼び出し

2. **メリット**
   - セキュリティの向上（アプリケーションに直接権限を与えない）
   - スケーラビリティ

## セキュリティ上の注意事項

- `ListUsers` APIは管理者レベルの権限であるため、最小権限の原則に従って慎重に設定してください
- 本番環境では、IAMロールの使用を強く推奨します
- アクセスキーを使用する場合は、定期的なローテーションを行ってください

## 動作確認

権限設定後、以下のログが表示されれば正常に動作しています：
```
Checking if email test@example.com already exists in user pool
Email test@example.com is available, proceeding with signup
```

重複メールアドレスの場合：
```
Email test@example.com already exists in user pool
```