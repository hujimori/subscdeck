package database

import (
	"database/sql"
	"log"
	"math/rand"
	"strconv"
	"time"

	"subscdeck/internal/model"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// InitDB initializes the SQLite database
func InitDB(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	// Create subscriptions table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS subscriptions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service_name TEXT NOT NULL,
		price INTEGER NOT NULL,
		usage_unit TEXT DEFAULT '',
		user_id TEXT DEFAULT '',
		created_at DATETIME NOT NULL
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return err
	}

	// Add usage_unit column to existing subscriptions table if it doesn't exist
	_, err = db.Exec("ALTER TABLE subscriptions ADD COLUMN usage_unit TEXT DEFAULT ''")
	if err != nil {
		// Column might already exist, ignore the error
	}

	// Add user_id column to existing subscriptions table if it doesn't exist
	_, err = db.Exec("ALTER TABLE subscriptions ADD COLUMN user_id TEXT DEFAULT ''")
	if err != nil {
		// Column might already exist, ignore the error
	}

	// Create subscription_usage_logs table if it doesn't exist
	createUsageLogsTableSQL := `
	CREATE TABLE IF NOT EXISTS subscription_usage_logs (
		log_id INTEGER PRIMARY KEY AUTOINCREMENT,
		subscription_id INTEGER NOT NULL,
		user_id TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (subscription_id) REFERENCES subscriptions (id)
	);`

	_, err = db.Exec(createUsageLogsTableSQL)
	if err != nil {
		return err
	}

	log.Println("Database initialized successfully")
	return nil
}

// GetDB returns the database instance
func GetDB() *sql.DB {
	return db
}

// GetAllSubscriptions retrieves all subscriptions from the database for a specific user
func GetAllSubscriptions(userID string) ([]model.Subscription, error) {
	// Debug log to check database query
	log.Printf("GetAllSubscriptions: Querying for userID: %s", userID)
	
	// First, let's see all subscriptions in the database for debugging
	debugRows, debugErr := db.Query("SELECT id, service_name, COALESCE(user_id, '') as user_id FROM subscriptions ORDER BY created_at DESC")
	if debugErr == nil {
		log.Printf("GetAllSubscriptions: DEBUG - All subscriptions in database:")
		for debugRows.Next() {
			var debugId int
			var debugService, debugUserID string
			debugRows.Scan(&debugId, &debugService, &debugUserID)
			log.Printf("GetAllSubscriptions: DEBUG - ID: %d, Service: %s, UserID: '%s'", debugId, debugService, debugUserID)
		}
		debugRows.Close()
	}
	
	rows, err := db.Query("SELECT id, service_name, price, COALESCE(usage_unit, '') as usage_unit, COALESCE(user_id, '') as user_id, created_at FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC", userID)
	if err != nil {
		log.Printf("GetAllSubscriptions: Database query error: %v", err)
		return nil, err
	}
	defer rows.Close()

	var subscriptions []model.Subscription
	for rows.Next() {
		var sub model.Subscription
		var id int
		err := rows.Scan(&id, &sub.ServiceName, &sub.Price, &sub.UsageUnit, &sub.UserID, &sub.CreatedAt)
		if err != nil {
			log.Printf("GetAllSubscriptions: Row scan error: %v", err)
			return nil, err
		}
		sub.ID = strconv.Itoa(id)
		subscriptions = append(subscriptions, sub)
		log.Printf("GetAllSubscriptions: Found subscription ID %d for userID %s, service: %s", id, sub.UserID, sub.ServiceName)
	}
	
	log.Printf("GetAllSubscriptions: Found %d subscriptions for userID: %s", len(subscriptions), userID)
	return subscriptions, rows.Err()
}

// CreateSubscription inserts a new subscription into the database
func CreateSubscription(serviceName string, price int, usageUnit string, userID string) (*model.Subscription, error) {
	result, err := db.Exec(
		"INSERT INTO subscriptions (service_name, price, usage_unit, user_id, created_at) VALUES (?, ?, ?, ?, ?)",
		serviceName, price, usageUnit, userID, time.Now(),
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &model.Subscription{
		ID:                strconv.FormatInt(id, 10),
		ServiceName:       serviceName,
		Price:             price,
		UsageUnit:         usageUnit,
		UserID:            userID,
		MonthlyUsageCount: 0, // 新規作成時は0回
		CreatedAt:         time.Now(),
	}, nil
}

// GetSubscriptionByID retrieves a single subscription by ID for a specific user
func GetSubscriptionByID(id string, userID string) (*model.Subscription, error) {
	row := db.QueryRow("SELECT id, service_name, price, COALESCE(usage_unit, '') as usage_unit, COALESCE(user_id, '') as user_id, created_at FROM subscriptions WHERE id = ? AND user_id = ?", id, userID)
	
	var sub model.Subscription
	var dbID int
	err := row.Scan(&dbID, &sub.ServiceName, &sub.Price, &sub.UsageUnit, &sub.UserID, &sub.CreatedAt)
	if err != nil {
		return nil, err
	}
	
	sub.ID = strconv.Itoa(dbID)
	return &sub, nil
}

// UpdateSubscription updates a subscription in the database for a specific user
func UpdateSubscription(id, serviceName string, price int, usageUnit string, userID string) (*model.Subscription, error) {
	_, err := db.Exec(
		"UPDATE subscriptions SET service_name = ?, price = ?, usage_unit = ? WHERE id = ? AND user_id = ?",
		serviceName, price, usageUnit, id, userID,
	)
	if err != nil {
		return nil, err
	}
	
	// Return the updated subscription
	return GetSubscriptionByID(id, userID)
}

// CreateUsageLog inserts a new usage log into the database
func CreateUsageLog(subscriptionID int, userID string) (*model.UsageLog, error) {
	result, err := db.Exec(
		"INSERT INTO subscription_usage_logs (subscription_id, user_id, created_at) VALUES (?, ?, ?)",
		subscriptionID, userID, time.Now(),
	)
	if err != nil {
		return nil, err
	}

	logID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &model.UsageLog{
		LogID:          int(logID),
		SubscriptionID: subscriptionID,
		UserID:         userID,
		CreatedAt:      time.Now(),
	}, nil
}

// GetMonthlyUsageCount retrieves the count of usage logs for a specific subscription in the current month
func GetMonthlyUsageCount(subscriptionID int, userID string) (int, error) {
	now := time.Now()
	firstDayOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	lastDayOfMonth := firstDayOfMonth.AddDate(0, 1, 0).Add(-time.Second)

	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM subscription_usage_logs WHERE subscription_id = ? AND user_id = ? AND created_at >= ? AND created_at <= ?",
		subscriptionID, userID, firstDayOfMonth, lastDayOfMonth,
	).Scan(&count)
	
	if err != nil {
		return 0, err
	}
	
	return count, nil
}

// GetMonthlyUsageCountByMonth retrieves the count of usage logs for a specific subscription by month
func GetMonthlyUsageCountByMonth(subscriptionID int, userID string, year int, month int) (int, error) {
	firstDayOfMonth := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	lastDayOfMonth := firstDayOfMonth.AddDate(0, 1, 0).Add(-time.Second)

	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM subscription_usage_logs WHERE subscription_id = ? AND user_id = ? AND created_at >= ? AND created_at <= ?",
		subscriptionID, userID, firstDayOfMonth, lastDayOfMonth,
	).Scan(&count)
	
	if err != nil {
		return 0, err
	}
	
	return count, nil
}

// DeleteSubscription removes a subscription from the database for a specific user
func DeleteSubscription(id string, userID string) error {
	_, err := db.Exec("DELETE FROM subscriptions WHERE id = ? AND user_id = ?", id, userID)
	return err
}

// GetUsageLogsBySubscriptionID retrieves all usage logs for a specific subscription
func GetUsageLogsBySubscriptionID(subscriptionID int, userID string) ([]model.UsageLog, error) {
	rows, err := db.Query(
		"SELECT log_id, subscription_id, user_id, created_at FROM subscription_usage_logs WHERE subscription_id = ? AND user_id = ? ORDER BY created_at DESC",
		subscriptionID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usageLogs []model.UsageLog
	for rows.Next() {
		var log model.UsageLog
		err := rows.Scan(&log.LogID, &log.SubscriptionID, &log.UserID, &log.CreatedAt)
		if err != nil {
			return nil, err
		}
		usageLogs = append(usageLogs, log)
	}

	return usageLogs, rows.Err()
}

// GetTestUserID finds the user ID for the test user
func GetTestUserID() (string, error) {
	var userID string
	// Look for any subscription or usage log with a recognizable pattern
	// Since we don't store username directly, we'll need to use a known test user ID
	// This is a placeholder - in production, you might want to store username mapping
	err := db.QueryRow(`
		SELECT DISTINCT user_id FROM subscriptions 
		WHERE user_id != '' 
		ORDER BY created_at DESC 
		LIMIT 1
	`).Scan(&userID)
	
	if err == sql.ErrNoRows {
		return "", nil // No test user found
	}
	if err != nil {
		return "", err
	}
	
	return userID, nil
}

// SeedDataForTestUser creates test data for the test user
func SeedDataForTestUser(testUserID string) error {
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
	defer tx.Rollback()

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

	// Generate random usage logs for the past 3 months
	// Create a weighted distribution for different days
	rand.Seed(time.Now().UnixNano())
	
	for i, subID := range subscriptionIDs {
		// Different usage patterns for different services
		var avgUsagePerMonth int
		if i == 0 { // Spotify - more frequent usage
			avgUsagePerMonth = 20
		} else { // Netflix - less frequent usage
			avgUsagePerMonth = 12
		}

		// Generate usage for past 3 months
		for month := 0; month < 3; month++ {
			monthDate := now.AddDate(0, -month, 0)
			daysInMonth := time.Date(monthDate.Year(), monthDate.Month()+1, 0, 0, 0, 0, 0, monthDate.Location()).Day()
			
			// Random usage count for this month (±30% variation)
			variation := rand.Intn(int(float64(avgUsagePerMonth)*0.6)) - int(float64(avgUsagePerMonth)*0.3)
			usageCount := avgUsagePerMonth + variation
			if usageCount < 0 {
				usageCount = 0
			}

			// Distribute usage across the month with weighted probability for weekdays
			for j := 0; j < usageCount; j++ {
				// Random day of month
				day := rand.Intn(daysInMonth) + 1
				usageDate := time.Date(monthDate.Year(), monthDate.Month(), day, 
					rand.Intn(24), rand.Intn(60), rand.Intn(60), 0, monthDate.Location())
				
				// Increase probability for certain days (Friday, Saturday)
				weekday := usageDate.Weekday()
				if weekday == time.Friday || weekday == time.Saturday {
					// 70% chance to keep, 30% chance to reroll
					if rand.Float64() > 0.7 {
						j-- // Reroll this usage
						continue
					}
				} else if weekday == time.Sunday || weekday == time.Monday {
					// 40% chance to keep, 60% chance to reroll
					if rand.Float64() > 0.4 {
						j-- // Reroll this usage
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

// Close closes the database connection
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}