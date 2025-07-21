# 利用履歴詳細API テストガイド

## エンドポイント
```
GET /api/subscriptions/:id/usage_details
```

## 認証
このエンドポイントは認証が必要です。アクセストークンをCookieまたはAuthorizationヘッダーに含めてください。

## レスポンス例

```json
{
  "usage_logs": [
    {
      "log_id": 10,
      "subscription_id": 1,
      "user_id": "user123",
      "created_at": "2025-07-20T15:30:00Z"
    },
    {
      "log_id": 9,
      "subscription_id": 1,
      "user_id": "user123",
      "created_at": "2025-07-19T10:15:00Z"
    }
  ],
  "monthly_stats": [
    {
      "month": "2025-06",
      "count": 15
    },
    {
      "month": "2025-07",
      "count": 20
    }
  ],
  "weekday_stats": [
    {
      "weekday": "月曜日",
      "count": 8
    },
    {
      "weekday": "火曜日",
      "count": 5
    },
    {
      "weekday": "水曜日",
      "count": 3
    },
    {
      "weekday": "木曜日",
      "count": 7
    },
    {
      "weekday": "金曜日",
      "count": 10
    },
    {
      "weekday": "土曜日",
      "count": 2
    },
    {
      "weekday": "日曜日",
      "count": 0
    }
  ],
  "most_popular_weekday": "金曜日",
  "last_month_count": 15,
  "this_month_count": 20,
  "month_comparison": 33.33
}
```

## テスト手順

1. アプリケーションを起動
```bash
AWS_PROFILE=subscdeck-dev go run main.go
```

2. ログイン
```bash
# ブラウザで http://localhost:8080 にアクセスしてログイン
```

3. サブスクリプションIDを確認
```bash
# ダッシュボードからサブスクリプションのIDを確認
# または GET /api/subscriptions でリストを取得
```

4. 利用履歴詳細を取得
```bash
# ブラウザの開発者ツールからConsoleで実行:
fetch('/api/subscriptions/1/usage_details')
  .then(res => res.json())
  .then(data => console.log(JSON.stringify(data, null, 2)))
```

## データの解説

- **usage_logs**: 全ての利用履歴（作成日時の降順）
- **monthly_stats**: 月ごとの利用回数集計
- **weekday_stats**: 曜日ごとの利用回数集計（全曜日を含む）
- **most_popular_weekday**: 最も利用の多い曜日
- **last_month_count**: 先月の利用回数
- **this_month_count**: 今月の利用回数
- **month_comparison**: 先月比（パーセンテージ）
  - 正の値: 増加
  - 負の値: 減少
  - 0: 変化なし
  - 100: 先月0回で今月利用ありの場合