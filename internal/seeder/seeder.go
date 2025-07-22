package seeder

import (
	"database/sql"
	"log"
	"math/rand"
	"time"
)

// SeedDevelopmentData creates test data for the development environment.
func SeedDevelopmentData(db *sql.DB, testUserID string) error {
	if testUserID == "" {
		log.Printf("No test user ID provided, skipping seed data")
		return nil
	}
	log.Printf("Starting seed data for test user: %s", testUserID)

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // Rollback on error

	// Delete existing usage logs for test user
	_, err = tx.Exec("DELETE FROM subscription_usage_logs WHERE user_id = ?", testUserID)
	if err != nil {
		log.Printf("Error deleting existing usage logs: %v", err)
		return err
	}

	// Delete existing subscriptions for test user
	_, err = tx.Exec("DELETE FROM subscriptions WHERE user_id = ?", testUserID)
	if err != nil {
		log.Printf("Error deleting existing subscriptions: %v", err)
		return err
	}

	// Create test subscriptions
	now := time.Now()
	subscriptions := []struct {
		name      string
		price     int
		usageUnit string
	}{
		{"Spotify", 980, "月額"},
		{"Netflix", 1490, "月額"},
	}

	subscriptionIDs := make([]int64, 0)
	for _, sub := range subscriptions {
		result, err := tx.Exec(
			"INSERT INTO subscriptions (service_name, price, usage_unit, user_id, created_at) VALUES (?, ?, ?, ?, ?)",
			sub.name, sub.price, sub.usageUnit, testUserID, now,
		)
		if err != nil {
			log.Printf("Error creating subscription %s: %v", sub.name, err)
			return err
		}
		id, err := result.LastInsertId()
		if err != nil {
			return err
		}
		subscriptionIDs = append(subscriptionIDs, id)
		log.Printf("Created subscription: %s (ID: %d)", sub.name, id)
	}

	// Generate random usage logs for the past 12 months
	rand.Seed(time.Now().UnixNano())

	for i, subID := range subscriptionIDs {
		var avgUsagePerMonth int
		if i == 0 { // Spotify
			avgUsagePerMonth = 20
		} else { // Netflix
			avgUsagePerMonth = 12
		}

		for month := 0; month < 12; month++ {
			monthDate := now.AddDate(0, -month, 0)
			daysInMonth := time.Date(monthDate.Year(), monthDate.Month()+1, 0, 0, 0, 0, 0, monthDate.Location()).Day()

			variation := rand.Intn(int(float64(avgUsagePerMonth)*0.6)) - int(float64(avgUsagePerMonth)*0.3)
			usageCount := avgUsagePerMonth + variation
			if usageCount < 0 {
				usageCount = 0
			}

			for j := 0; j < usageCount; j++ {
				day := rand.Intn(daysInMonth) + 1
				usageDate := time.Date(monthDate.Year(), monthDate.Month(), day,
					rand.Intn(24), rand.Intn(60), rand.Intn(60), 0, monthDate.Location())

				weekday := usageDate.Weekday()
				if weekday == time.Friday || weekday == time.Saturday {
					if rand.Float64() > 0.7 {
						j-- 
						continue
					}
				} else if weekday == time.Sunday || weekday == time.Monday {
					if rand.Float64() > 0.4 {
						j-- 
						continue
					}
				}

				_, err := tx.Exec(
					"INSERT INTO subscription_usage_logs (subscription_id, user_id, created_at) VALUES (?, ?, ?)",
					subID, testUserID, usageDate,
				)
				if err != nil {
					log.Printf("Error creating usage log: %v", err)
					return err
				}
			}
			log.Printf("Created %d usage logs for subscription ID %d in %s",
				usageCount, subID, monthDate.Format("2006-01"))
		}
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	log.Printf("Successfully seeded test data for user: %s", testUserID)
	return nil
}