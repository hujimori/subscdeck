# subscdeck

Go Echo v4を使用したWebサーバーで、AWS Cognito認証を実装しています。

## セットアップ

1. 環境変数の設定
```bash
cp .env.example .env
```

以下の環境変数を設定してください：
- `COGNITO_USER_POOL_ID`: AWS CognitoのユーザープールID
- `COGNITO_APP_CLIENT_ID`: AWS Cognitoのアプリケーションクライアント
- `AWS_REGION`: AWSリージョン（例: ap-northeast-1）
- `PORT`: サーバーのポート番号（デフォルト: 8080）

2. 依存関係のインストール
```bash
go mod download
```

3. サーバーの起動
```bash
go run main.go
```

## エンドポイント

- `GET /` - 公開エンドポイント（認証不要）
- `POST /login` - ログインエンドポイント（ユーザー名とパスワードでJWTトークンを取得）
- `GET /protected` - 保護されたエンドポイント（Cognito JWT認証が必要）

## 認証

### ログイン

`/login`エンドポイントにPOSTリクエストを送信してJWTトークンを取得します：

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your-username","password":"your-password"}'
```

レスポンス例：
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJjdHkiOiJKV1QiLC...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### 保護されたエンドポイントへのアクセス

保護されたエンドポイントにアクセスするには、AuthorizationヘッダーにCognitoのアクセストークンを含める必要があります：

```
Authorization: Bearer <your-cognito-access-token>
```

## 実装の詳細

- Echo v4フレームワークを使用
- AWS SDK v2を使用してCognito認証を実装
- ログイン時はInitiateAuth APIを使用（USER_PASSWORD_AUTHフロー）
- CognitoのJWKS（JSON Web Key Set）エンドポイントからキーを取得してJWT検証を実行
- JWKSは1時間キャッシュされます
- アクセストークンのみを受け付けます（IDトークンは拒否）