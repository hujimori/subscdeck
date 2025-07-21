package model

import "time"

// Subscription represents a subscription service
type Subscription struct {
	ID                string    `json:"id"`
	ServiceName       string    `json:"service_name"`
	Price             int       `json:"price"`
	UsageUnit         string    `json:"usage_unit"`
	UserID            string    `json:"user_id"`
	MonthlyUsageCount int       `json:"monthly_usage_count"`
	CreatedAt         time.Time `json:"created_at"`
}

// UsageLog represents a usage record for a subscription
type UsageLog struct {
	LogID          int       `json:"log_id"`
	SubscriptionID int       `json:"subscription_id"`
	UserID         string    `json:"user_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// UsageDetailsResponse represents the detailed usage information response
type UsageDetailsResponse struct {
	UsageLogs          []UsageLog          `json:"usage_logs"`
	MonthlyStats       []MonthlyUsageStat  `json:"monthly_stats"`
	WeekdayStats       []WeekdayUsageStat  `json:"weekday_stats"`
	MostPopularWeekday string              `json:"most_popular_weekday"`
	LastMonthCount     int                 `json:"last_month_count"`
	ThisMonthCount     int                 `json:"this_month_count"`
	MonthComparison    float64             `json:"month_comparison"` // Percentage change
}

// MonthlyUsageStat represents usage statistics for a specific month
type MonthlyUsageStat struct {
	Month string `json:"month"` // Format: YYYY-MM
	Count int    `json:"count"`
}

// WeekdayUsageStat represents usage statistics for a specific weekday
type WeekdayUsageStat struct {
	Weekday string `json:"weekday"` // Monday, Tuesday, etc.
	Count   int    `json:"count"`
}