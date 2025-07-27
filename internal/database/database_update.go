package database

import (
	"fmt"
	"log"
	"time"
)

// UpdateUsageCount updates the usage count of a subscription to a specific value
func UpdateUsageCount(subscriptionID int, userID string, newCount int) error {
	// First, verify the subscription belongs to the user
	var exists bool
	err := db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM subscriptions WHERE id = ? AND user_id = ?)",
		subscriptionID, userID,
	).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("subscription not found or does not belong to user")
	}

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete all existing usage logs for this subscription
	_, err = tx.Exec(
		"DELETE FROM subscription_usage_logs WHERE subscription_id = ? AND user_id = ?",
		subscriptionID, userID,
	)
	if err != nil {
		return err
	}

	// Insert new usage logs to match the desired count
	now := time.Now()
	for i := 0; i < newCount; i++ {
		// Spread out the timestamps slightly to maintain order
		timestamp := now.Add(time.Duration(i) * time.Second)
		_, err = tx.Exec(
			"INSERT INTO subscription_usage_logs (subscription_id, user_id, created_at) VALUES (?, ?, ?)",
			subscriptionID, userID, timestamp,
		)
		if err != nil {
			return err
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return err
	}

	log.Printf("Updated usage count for subscription %d to %d", subscriptionID, newCount)
	return nil
}