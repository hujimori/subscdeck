-- テストデータ生成スクリプト
-- 既存のサブスクリプションに対して1年分の利用履歴を追加

-- 注意: このスクリプトを実行する前に、サブスクリプションが登録されている必要があります
-- subscription_id = 1 のサブスクリプションに対してデータを追加します

-- 既存のテストデータを削除（オプション）
-- DELETE FROM subscription_usage_logs WHERE subscription_id = 1;

-- 1年分のデータを生成（各月ランダムな回数）
-- 2024年7月から2025年7月まで
WITH RECURSIVE dates(date) AS (
  SELECT date('2024-07-01')
  UNION ALL
  SELECT date(date, '+1 day')
  FROM dates
  WHERE date < date('2025-07-20')
)
INSERT INTO subscription_usage_logs (subscription_id, user_id, created_at)
SELECT 
  1, -- subscription_id (変更してください)
  (SELECT user_id FROM subscriptions WHERE id = 1), -- 対応するuser_idを取得
  datetime(date || ' ' || printf('%02d:%02d:%02d', 
    abs(random()) % 24,
    abs(random()) % 60,
    abs(random()) % 60
  ))
FROM dates
WHERE 
  -- ランダムに利用日を選択（約30%の確率で利用）
  abs(random()) % 100 < 30
  -- 週末は利用確率を下げる（土日は15%）
  AND (
    strftime('%w', date) NOT IN ('0', '6') 
    OR abs(random()) % 100 < 50
  );

-- 各サブスクリプションに対してデータを生成する汎用版
-- 全てのサブスクリプションに対してランダムなデータを生成
INSERT INTO subscription_usage_logs (subscription_id, user_id, created_at)
SELECT 
  s.id,
  s.user_id,
  datetime(
    date('now', '-' || (abs(random()) % 365) || ' days') || ' ' || 
    printf('%02d:%02d:%02d', 
      abs(random()) % 24,
      abs(random()) % 60,
      abs(random()) % 60
    )
  )
FROM 
  subscriptions s,
  (SELECT 1 FROM generate_series(1, 100)) -- 各サブスクリプションに約100件のデータ
WHERE 
  abs(random()) % 100 < 30; -- 30%の確率でデータを生成