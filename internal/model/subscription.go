package model

import "time"

// Subscription represents a subscription service
type Subscription struct {
	ID          string    `json:"id"`
	ServiceName string    `json:"service_name"`
	Price       int       `json:"price"`
	CreatedAt   time.Time `json:"created_at"`
}