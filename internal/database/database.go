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
		created_at DATETIME NOT NULL
	);`

	_, err = db.Exec(createTableSQL)
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

// GetAllSubscriptions retrieves all subscriptions from the database
func GetAllSubscriptions() ([]model.Subscription, error) {
	rows, err := db.Query("SELECT id, service_name, price, created_at FROM subscriptions ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subscriptions []model.Subscription
	for rows.Next() {
		var sub model.Subscription
		var id int
		err := rows.Scan(&id, &sub.ServiceName, &sub.Price, &sub.CreatedAt)
		if err != nil {
			return nil, err
		}
		sub.ID = strconv.Itoa(id)
		subscriptions = append(subscriptions, sub)
	}

	return subscriptions, rows.Err()
}

// CreateSubscription inserts a new subscription into the database
func CreateSubscription(serviceName string, price int) (*model.Subscription, error) {
	result, err := db.Exec(
		"INSERT INTO subscriptions (service_name, price, created_at) VALUES (?, ?, ?)",
		serviceName, price, time.Now(),
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &model.Subscription{
		ID:          strconv.FormatInt(id, 10),
		ServiceName: serviceName,
		Price:       price,
		CreatedAt:   time.Now(),
	}, nil
}

// DeleteSubscription removes a subscription from the database
func DeleteSubscription(id string) error {
	_, err := db.Exec("DELETE FROM subscriptions WHERE id = ?", id)
	return err
}

// Close closes the database connection
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}