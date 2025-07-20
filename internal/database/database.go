package database

import (
	"database/sql"
	"log"
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
	rows, err := db.Query("SELECT id, service_name, price, COALESCE(usage_unit, '') as usage_unit, COALESCE(user_id, '') as user_id, created_at FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subscriptions []model.Subscription
	for rows.Next() {
		var sub model.Subscription
		var id int
		err := rows.Scan(&id, &sub.ServiceName, &sub.Price, &sub.UsageUnit, &sub.UserID, &sub.CreatedAt)
		if err != nil {
			return nil, err
		}
		sub.ID = strconv.Itoa(id)
		subscriptions = append(subscriptions, sub)
	}

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

// Close closes the database connection
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}