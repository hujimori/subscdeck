package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// データベースを開く
	db, err := sql.Open("sqlite3", "subscdeck.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// 全てのサブスクリプションを取得
	rows, err := db.Query("SELECT id, user_id FROM subscriptions")
	if err != nil {
		log.Fatal("Failed to query subscriptions:", err)
	}
	defer rows.Close()

	type Subscription struct {
		ID     int
		UserID string
	}

	var subscriptions []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.ID, &sub.UserID); err != nil {
			log.Printf("Failed to scan subscription: %v", err)
			continue
		}
		subscriptions = append(subscriptions, sub)
	}

	if len(subscriptions) == 0 {
		log.Fatal("No subscriptions found. Please create at least one subscription first.")
	}

	// 各サブスクリプションに対してテストデータを生成
	for _, sub := range subscriptions {
		log.Printf("Generating test data for subscription ID: %d (User: %s)", sub.ID, sub.UserID)
		
		// 過去1年間のデータを生成
		endDate := time.Now()
		startDate := endDate.AddDate(-1, 0, 0)
		
		insertCount := 0
		for d := startDate; d.Before(endDate); d = d.AddDate(0, 0, 1) {
			// 曜日による利用確率の調整
			weekday := d.Weekday()
			usageProbability := 0.3 // デフォルト30%
			
			// 平日は利用確率を上げる
			if weekday >= time.Monday && weekday <= time.Friday {
				usageProbability = 0.4 // 40%
			} else {
				usageProbability = 0.15 // 週末は15%
			}
			
			// 月による変動も追加（夏は利用が増える想定）
			month := d.Month()
			if month >= time.June && month <= time.August {
				usageProbability += 0.1
			}
			
			// ランダムに利用日を決定
			if rand.Float64() < usageProbability {
				// その日の利用回数（1-3回）
				usageCount := rand.Intn(3) + 1
				
				for i := 0; i < usageCount; i++ {
					// ランダムな時刻を生成
					hour := rand.Intn(24)
					minute := rand.Intn(60)
					second := rand.Intn(60)
					
					timestamp := time.Date(d.Year(), d.Month(), d.Day(), hour, minute, second, 0, d.Location())
					
					// データベースに挿入
					_, err := db.Exec(
						"INSERT INTO subscription_usage_logs (subscription_id, user_id, created_at) VALUES (?, ?, ?)",
						sub.ID, sub.UserID, timestamp,
					)
					if err != nil {
						log.Printf("Failed to insert usage log: %v", err)
						continue
					}
					insertCount++
				}
			}
		}
		
		log.Printf("Inserted %d usage logs for subscription ID: %d", insertCount, sub.ID)
	}

	// 統計情報を表示
	var totalCount int
	err = db.QueryRow("SELECT COUNT(*) FROM subscription_usage_logs").Scan(&totalCount)
	if err == nil {
		log.Printf("Total usage logs in database: %d", totalCount)
	}

	log.Println("Test data generation completed!")
}