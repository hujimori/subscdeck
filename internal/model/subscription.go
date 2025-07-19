package model

import "time"

// Subscription represents a subscription service
type Subscription struct {
	ID          string    `json:"id"`
	ServiceName string    `json:"service_name"`
	Price       int       `json:"price"`
	UsageUnit   string    `json:"usage_unit"`
	CreatedAt   time.Time `json:"created_at"`
}

// UsageLog represents a usage record for a subscription
type UsageLog struct {
	LogID          int       `json:"log_id"`
	SubscriptionID int       `json:"subscription_id"`
	UserID         string    `json:"user_id"`
	CreatedAt      time.Time `json:"created_at"`
}