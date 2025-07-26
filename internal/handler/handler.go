package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hujimori/subscdeck/internal/database"
	"github.com/hujimori/subscdeck/internal/middleware"
	"github.com/hujimori/subscdeck/internal/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/labstack/echo/v4"
)


type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyRequest struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

type ResendCodeRequest struct {
	Username string `json:"username"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type CreateSubscriptionRequest struct {
	ServiceName string `json:"service_name"`
	Price       int    `json:"price"`
	UsageUnit   string `json:"usage_unit"`
}

type DeleteSubscriptionRequest struct {
	ID string `form:"id"`
}

type EditSubscriptionRequest struct {
	ID string `query:"id"`
}

type UpdateSubscriptionRequest struct {
	ServiceName string `json:"service_name"`
	Price       int    `json:"price"`
	UsageUnit   string `json:"usage_unit"`
}

type UpdateSubscriptionFormRequest struct {
	ID          string `form:"id"`
	ServiceName string `form:"service_name"`
	Price       int    `form:"price"`
	UsageUnit   string `form:"usage_unit"`
}

type CreateUsageLogRequest struct {
	SubscriptionID int `json:"subscription_id"`
}

type UsageStatResponse struct {
	Month       string `json:"month"`
	CostPerUse  int    `json:"cost_per_use"`
}

type UsageDataInfo struct {
	TotalMonths int `json:"total_months"`
	SuggestedPeriod int `json:"suggested_period"`
	FirstDataOffset int `json:"first_data_offset"`
	LastDataOffset int `json:"last_data_offset"`
}

var (
	cognitoClient *cognitoidentityprovider.Client
)

// SetCognitoClient sets the Cognito client for the handler
func SetCognitoClient(client *cognitoidentityprovider.Client) {
	cognitoClient = client
}

func PublicHandler(c echo.Context) error {
	tmpl, err := template.ParseFiles("web/template/login.html")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load template")
	}
	return tmpl.Execute(c.Response(), nil)
}

func ProtectedHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Protected API endpoint - Authentication successful")
}

func DashboardHandler(c echo.Context) error {
	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	userID := "unknown_user" // Default fallback
	if userContext != nil {
		if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
			userID = userClaims.Subject
		}
	}
	
	// Debug log to check user ID extraction
	log.Printf("DashboardHandler: UserID extracted from JWT: %s", userID)

	// Transfer test data to user if this is their first time
	err := database.TransferTestDataToUser(userID)
	if err != nil {
		log.Printf("Warning: Failed to transfer test data: %v", err)
	}

	// Get all subscriptions from database for this user
	subscriptions, err := database.GetAllSubscriptions(userID)
	if err != nil {
		log.Printf("Error fetching subscriptions: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch subscriptions")
	}

	// Get monthly usage count for each subscription
	for i := range subscriptions {
		// Convert subscription ID from string to int
		subscriptionID, err := strconv.Atoi(subscriptions[i].ID)
		if err != nil {
			log.Printf("Error converting subscription ID to int: %v", err)
			subscriptions[i].MonthlyUsageCount = 0
			continue
		}
		
		// Get monthly usage count
		count, err := database.GetMonthlyUsageCount(subscriptionID, userID)
		if err != nil {
			log.Printf("Error fetching monthly usage count for subscription %s: %v", subscriptions[i].ID, err)
			subscriptions[i].MonthlyUsageCount = 0
		} else {
			subscriptions[i].MonthlyUsageCount = count
		}
	}

	tmpl, err := template.ParseFiles("web/template/dashboard.html")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load template")
	}
	
	// JSONエンコードしてテンプレートに渡す
	subscriptionsJSON, err := json.Marshal(subscriptions)
	if err != nil {
		log.Printf("Error marshaling subscriptions: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process subscriptions")
	}
	
	// Check if user is logged in by checking if user context exists
	isLoggedIn := userContext != nil
	
	// Pass subscriptions and login status to template
	data := struct {
		SubscriptionsJSON template.JS
		IsLoggedIn        bool
	}{
		SubscriptionsJSON: template.JS(subscriptionsJSON),
		IsLoggedIn:        isLoggedIn,
	}
	
	return tmpl.Execute(c.Response(), data)
}

// calculateSecretHash computes the SECRET_HASH for Cognito
func calculateSecretHash(username, clientID, clientSecret string) string {
	message := username + clientID
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func LoginHandler(c echo.Context) error {
	// Parse request body
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Get environment variables
	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	clientID := os.Getenv("COGNITO_APP_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_APP_CLIENT_SECRET")
	
	if userPoolID == "" || clientID == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
	}

	// Prepare InitiateAuth input
	authParams := map[string]string{
		"USERNAME": req.Username,
		"PASSWORD": req.Password,
	}

	// Add SECRET_HASH if client secret is configured
	if clientSecret != "" {
		secretHash := calculateSecretHash(req.Username, clientID, clientSecret)
		authParams["SECRET_HASH"] = secretHash
	}

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserPasswordAuth,
		ClientId:       aws.String(clientID),
		AuthParameters: authParams,
	}

	// Log the request parameters for debugging
	log.Printf("Attempting login for user: %s", req.Username)
	log.Printf("Using User Pool ID: %s", userPoolID)
	log.Printf("Using Client ID: %s", clientID)
	log.Printf("Client Secret configured: %t", clientSecret != "")

	// Call Cognito InitiateAuth
	result, err := cognitoClient.InitiateAuth(c.Request().Context(), input)
	if err != nil {
		// Log the error for debugging
		log.Printf("Cognito InitiateAuth error: %v", err)
		log.Printf("Error type: %T", err)
		
		// Check for specific error types with improved UX messaging
		if strings.Contains(err.Error(), "NotAuthorizedException") {
			return echo.NewHTTPError(http.StatusUnauthorized, "ユーザー名またはパスワードが正しくありません。入力内容をご確認ください。")
		}
		if strings.Contains(err.Error(), "UserNotFoundException") {
			return echo.NewHTTPError(http.StatusUnauthorized, "ユーザーが見つかりません。ユーザー名またはメールアドレスをご確認いただくか、アカウント作成ページから新規登録してください。")
		}
		if strings.Contains(err.Error(), "UserNotConfirmedException") {
			return echo.NewHTTPError(http.StatusUnauthorized, "アカウントの確認が完了していません。メールで送信された認証コードを入力して、アカウントを有効化してください。")
		}
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return echo.NewHTTPError(http.StatusBadRequest, "入力内容に誤りがあります。ユーザー名またはメールアドレスとパスワードを正しく入力してください。")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Authentication failed: %v", err))
	}

	// Check if we got authentication result
	if result.AuthenticationResult == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "No authentication result received")
	}

	// Set JWT as HTTPOnly cookie
	accessToken := aws.ToString(result.AuthenticationResult.AccessToken)
	cookie := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		Path:     "/",
		MaxAge:   int(result.AuthenticationResult.ExpiresIn),
	}
	c.SetCookie(cookie)

	// Return JSON response for AJAX requests
	response := LoginResponse{
		AccessToken:  accessToken,
		IDToken:      aws.ToString(result.AuthenticationResult.IdToken),
		RefreshToken: aws.ToString(result.AuthenticationResult.RefreshToken),
		ExpiresIn:    result.AuthenticationResult.ExpiresIn,
		TokenType:    aws.ToString(result.AuthenticationResult.TokenType),
	}

	return c.JSON(http.StatusOK, response)
}

func GetSubscriptionsHandler(c echo.Context) error {
	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}
	
	// Debug log to check user ID extraction
	log.Printf("GetSubscriptionsHandler: UserID extracted from JWT: %s", userID)

	// Transfer test data to user if this is their first time
	err := database.TransferTestDataToUser(userID)
	if err != nil {
		log.Printf("Warning: Failed to transfer test data: %v", err)
	}

	// Get all subscriptions from database for this user
	subscriptions, err := database.GetAllSubscriptions(userID)
	if err != nil {
		log.Printf("Error fetching subscriptions: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch subscriptions")
	}

	// Get monthly usage count for each subscription
	for i := range subscriptions {
		// Convert subscription ID from string to int
		subscriptionID, err := strconv.Atoi(subscriptions[i].ID)
		if err != nil {
			log.Printf("Error converting subscription ID to int: %v", err)
			subscriptions[i].MonthlyUsageCount = 0
			continue
		}
		
		// Get monthly usage count
		count, err := database.GetMonthlyUsageCount(subscriptionID, userID)
		if err != nil {
			log.Printf("Error fetching monthly usage count for subscription %s: %v", subscriptions[i].ID, err)
			subscriptions[i].MonthlyUsageCount = 0
		} else {
			subscriptions[i].MonthlyUsageCount = count
		}
	}

	// Return subscriptions as JSON
	return c.JSON(http.StatusOK, subscriptions)
}

func CreateSubscriptionHandler(c echo.Context) error {
	// Parse request body
	var req CreateSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate input
	if req.ServiceName == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Service name is required")
	}
	if req.Price <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Price must be greater than 0")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Create new subscription in database
	newSub, err := database.CreateSubscription(req.ServiceName, req.Price, req.UsageUnit, userID)
	if err != nil {
		log.Printf("Error creating subscription: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create subscription")
	}

	// Return the created subscription
	return c.JSON(http.StatusCreated, newSub)
}

func DeleteSubscriptionHandler(c echo.Context) error {
	// Parse request body
	var req DeleteSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate input
	if req.ID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ID is required")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Delete from database (only user's own subscription)
	err := database.DeleteSubscription(req.ID, userID)
	if err != nil {
		log.Printf("Error deleting subscription: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete subscription")
	}

	// Redirect to dashboard
	return c.Redirect(http.StatusSeeOther, "/dashboard")
}

func EditSubscriptionHandler(c echo.Context) error {
	// Parse query parameter
	var req EditSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request parameters")
	}

	// Validate input
	if req.ID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ID is required")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Get subscription from database for this user
	subscription, err := database.GetSubscriptionByID(req.ID, userID)
	if err != nil {
		log.Printf("Error fetching subscription: %v", err)
		return echo.NewHTTPError(http.StatusNotFound, "Subscription not found")
	}

	// Check if user is logged in by checking if user context exists
	isLoggedIn := userContext != nil
	
	// Load template
	tmpl, err := template.ParseFiles("web/template/edit.html")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load template")
	}
	
	// Pass subscription data and login status to template
	data := struct {
		Subscription *model.Subscription
		IsLoggedIn   bool
	}{
		Subscription: subscription,
		IsLoggedIn:   isLoggedIn,
	}
	
	return tmpl.Execute(c.Response(), data)
}

func UpdateSubscriptionHandler(c echo.Context) error {
	// Get ID from URL path
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ID is required")
	}

	// Parse request body
	var req UpdateSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate input
	if req.ServiceName == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Service name is required")
	}
	if req.Price <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Price must be greater than 0")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Update subscription in database
	updatedSub, err := database.UpdateSubscription(id, req.ServiceName, req.Price, req.UsageUnit, userID)
	if err != nil {
		log.Printf("Error updating subscription: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update subscription")
	}

	// Return the updated subscription
	return c.JSON(http.StatusOK, updatedSub)
}

func UpdateSubscriptionFormHandler(c echo.Context) error {
	// Parse form data
	var req UpdateSubscriptionFormRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid form data")
	}

	// Validate input
	if req.ID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ID is required")
	}
	if req.ServiceName == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Service name is required")
	}
	if req.Price <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Price must be greater than 0")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Update subscription in database
	_, err := database.UpdateSubscription(req.ID, req.ServiceName, req.Price, req.UsageUnit, userID)
	if err != nil {
		log.Printf("Error updating subscription: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update subscription")
	}

	// Redirect to dashboard
	return c.Redirect(http.StatusSeeOther, "/dashboard")
}

func CreateUsageLogHandler(c echo.Context) error {
	// Parse request body
	var req CreateUsageLogRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate input
	if req.SubscriptionID <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Valid subscription_id is required")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Create usage log in database
	usageLog, err := database.CreateUsageLog(req.SubscriptionID, userID)
	if err != nil {
		log.Printf("Error creating usage log: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create usage log")
	}

	// Return the created usage log
	return c.JSON(http.StatusCreated, usageLog)
}

func GetUsageStatsHandler(c echo.Context) error {
	// Get subscription ID from URL parameter
	subscriptionID := c.Param("id")
	if subscriptionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Subscription ID is required")
	}

	// Validate that subscription ID is a valid number
	subscriptionIDInt, err := strconv.Atoi(subscriptionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid subscription ID")
	}

	// Get period parameter (default: 3 months)
	periodParam := c.QueryParam("period")
	monthsBack := 3 // default
	getAllData := false
	
	if periodParam != "" {
		if periodParam == "all" {
			getAllData = true
			monthsBack = 60 // Maximum 5 years of data
		} else if p, err := strconv.Atoi(periodParam); err == nil && (p == 3 || p == 6 || p == 12) {
			monthsBack = p
		}
	}

	// Get offset parameter (default: 0)
	offsetParam := c.QueryParam("offset")
	monthOffset := 0
	if offsetParam != "" {
		if o, err := strconv.Atoi(offsetParam); err == nil && o >= 0 {
			monthOffset = o
		}
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Get subscription information from database
	subscription, err := database.GetSubscriptionByID(subscriptionID, userID)
	if err != nil {
		log.Printf("Error fetching subscription for user %s: %v", userID, err)
		return echo.NewHTTPError(http.StatusNotFound, "Subscription not found")
	}

	// Calculate usage statistics for the specified period with offset
	var usageStats []UsageStatResponse
	now := time.Now()
	
	for i := monthsBack - 1; i >= 0; i-- {
		targetDate := now.AddDate(0, -(i + monthOffset), 0)
		year := targetDate.Year()
		month := int(targetDate.Month())
		
		// Get usage count for this month
		usageCount, err := database.GetMonthlyUsageCountByMonth(subscriptionIDInt, userID, year, month)
		if err != nil {
			log.Printf("Error fetching monthly usage count for subscription %s, year %d, month %d: %v", subscriptionID, year, month, err)
			continue
		}
		
		// Skip months with no data when getting all data
		if getAllData && usageCount == 0 {
			continue
		}
		
		// Calculate cost per use
		var costPerUse int
		if usageCount > 0 {
			costPerUse = subscription.Price / usageCount
		} else {
			costPerUse = subscription.Price // If no usage, cost per use equals full price
		}
		
		monthStr := fmt.Sprintf("%04d-%02d", year, month)
		usageStats = append(usageStats, UsageStatResponse{
			Month:      monthStr,
			CostPerUse: costPerUse,
		})
	}

	return c.JSON(http.StatusOK, usageStats)
}

func GetUsageDataInfoHandler(c echo.Context) error {
	// Get subscription ID from URL parameter
	subscriptionID := c.Param("id")
	if subscriptionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Subscription ID is required")
	}

	// Validate that subscription ID is a valid number
	subscriptionIDInt, err := strconv.Atoi(subscriptionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid subscription ID")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Get subscription information from database to verify access
	_, err = database.GetSubscriptionByID(subscriptionID, userID)
	if err != nil {
		log.Printf("Error fetching subscription for user %s: %v", userID, err)
		return echo.NewHTTPError(http.StatusNotFound, "Subscription not found")
	}

	// Find data range
	now := time.Now()
	firstDataOffset := -1
	lastDataOffset := 0
	totalMonths := 0
	
	// Check up to 60 months back to find data range
	for i := 0; i < 60; i++ {
		targetDate := now.AddDate(0, -i, 0)
		year := targetDate.Year()
		month := int(targetDate.Month())
		
		usageCount, err := database.GetMonthlyUsageCountByMonth(subscriptionIDInt, userID, year, month)
		if err != nil {
			continue
		}
		
		if usageCount > 0 {
			if firstDataOffset == -1 {
				firstDataOffset = i
			}
			lastDataOffset = i
			totalMonths++
		}
	}

	// If no data found, set defaults
	if firstDataOffset == -1 {
		firstDataOffset = 0
		lastDataOffset = 0
	}

	// Determine suggested period based on data availability
	var suggestedPeriod int
	if totalMonths <= 3 {
		suggestedPeriod = 3
	} else if totalMonths <= 6 {
		suggestedPeriod = 6
	} else {
		suggestedPeriod = 12
	}

	return c.JSON(http.StatusOK, UsageDataInfo{
		TotalMonths:     totalMonths,
		SuggestedPeriod: suggestedPeriod,
		FirstDataOffset: firstDataOffset,
		LastDataOffset:  lastDataOffset,
	})
}

func LogoutHandler(c echo.Context) error {
	// Create a cookie with the same name but with an expired date to delete it
	cookie := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		Path:     "/",
		MaxAge:   -1, // Negative MaxAge means delete the cookie
		Expires:  time.Now().Add(-time.Hour), // Set expiration to the past
	}
	c.SetCookie(cookie)

	// Redirect to login page
	return c.Redirect(http.StatusSeeOther, "/")
}

func SignupPageHandler(c echo.Context) error {
	tmpl, err := template.ParseFiles("web/template/signup.html")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load template")
	}
	return tmpl.Execute(c.Response(), nil)
}

func VerifyPageHandler(c echo.Context) error {
	tmpl, err := template.ParseFiles("web/template/verify.html")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load template")
	}
	return tmpl.Execute(c.Response(), nil)
}

func SignupHandler(c echo.Context) error {
	// Parse request body
	var req SignupRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ユーザー名、メールアドレス、パスワードは全て必須です")
	}

	// Get environment variables
	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	clientID := os.Getenv("COGNITO_APP_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_APP_CLIENT_SECRET")
	
	if userPoolID == "" || clientID == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
	}

	// Use the provided username directly
	// Calculate SECRET_HASH if client secret is configured
	var secretHash *string
	if clientSecret != "" {
		hash := calculateSecretHash(req.Username, clientID, clientSecret)
		secretHash = aws.String(hash)
	}

	// Prepare SignUp input
	signUpInput := &cognitoidentityprovider.SignUpInput{
		ClientId:   aws.String(clientID),
		Username:   aws.String(req.Username),
		Password:   aws.String(req.Password),
		SecretHash: secretHash,
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(req.Email),
			},
		},
	}

	// 事前チェック：メールアドレスが既に使用されていないか確認
	// ListUsers APIを使用してメールアドレスの重複をチェック
	listUsersInput := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(userPoolID),
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", req.Email)),
		Limit:      aws.Int32(1), // 1件でも見つかれば重複と判断
	}

	log.Printf("Checking if email %s already exists in user pool", req.Email)
	listResult, err := cognitoClient.ListUsers(c.Request().Context(), listUsersInput)
	if err != nil {
		log.Printf("Error checking for existing email: %v", err)
		// ListUsers APIの権限エラーの場合でも、ユーザーに分かりやすいメッセージを返す
		if strings.Contains(err.Error(), "UnrecognizedClientException") || strings.Contains(err.Error(), "AccessDeniedException") {
			log.Printf("ListUsers API permission error. Application needs appropriate IAM permissions to use ListUsers API.")
			// 権限エラーの場合は処理を続行せず、設定エラーとして返す
			return echo.NewHTTPError(http.StatusInternalServerError, "サーバー設定エラー：メールアドレスの重複チェックができません。管理者に連絡してください。")
		}
		// その他のエラーの場合も安全のため処理を中断
		return echo.NewHTTPError(http.StatusInternalServerError, "メールアドレスの確認中にエラーが発生しました。")
	}

	// ユーザーが見つかった場合（メールアドレスが既に使用されている）
	if listResult != nil && len(listResult.Users) > 0 {
		log.Printf("Email %s already exists in user pool", req.Email)
		return echo.NewHTTPError(http.StatusBadRequest, "このメールアドレスは既に登録されています。ログインページから既存のアカウントでログインするか、別のメールアドレスをお試しください。")
	}

	log.Printf("Email %s is available, proceeding with signup", req.Email)

	// Log the request parameters for debugging
	log.Printf("Attempting signup for email: %s with username: %s", req.Email, req.Username)
	log.Printf("Using User Pool ID: %s", userPoolID)
	log.Printf("Using Client ID: %s", clientID)

	// Call Cognito SignUp
	result, err := cognitoClient.SignUp(c.Request().Context(), signUpInput)
	if err != nil {
		// Log the error for debugging
		log.Printf("Cognito SignUp error: %v", err)
		
		// Check for specific error types with improved UX messaging
		if strings.Contains(err.Error(), "UsernameExistsException") {
			return echo.NewHTTPError(http.StatusBadRequest, "このユーザー名は既に使用されています。別のユーザー名を選択してください。")
		}
		if strings.Contains(err.Error(), "AliasExistsException") {
			return echo.NewHTTPError(http.StatusBadRequest, "このメールアドレスは既に登録されています。ログインページから既存のアカウントでログインするか、別のメールアドレスをお試しください。")
		}
		if strings.Contains(err.Error(), "InvalidPasswordException") {
			return echo.NewHTTPError(http.StatusBadRequest, "パスワードが要件を満たしていません。8文字以上で大文字・小文字・数字を含むパスワードを設定してください。")
		}
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return echo.NewHTTPError(http.StatusBadRequest, "入力内容に誤りがあります。ユーザー名は3-20文字の英数字とアンダースコアのみ使用できます。")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("アカウント作成に失敗しました: %v", err))
	}

	// Log successful signup
	log.Printf("User signup successful for: %s, UserConfirmed: %v", req.Username, result.UserConfirmed)

	// Return redirect to verify page
	return c.JSON(http.StatusOK, map[string]any{
		"message": "アカウントが作成されました。認証コード入力ページに移動します。",
		"userSub": aws.ToString(result.UserSub),
		"userConfirmed": result.UserConfirmed,
		"redirect": "/verify",
	})
}

func VerifyHandler(c echo.Context) error {
	// Parse request body
	var req VerifyRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate input
	if req.Username == "" || req.Code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username and verification code are required")
	}

	// Get environment variables
	clientID := os.Getenv("COGNITO_APP_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_APP_CLIENT_SECRET")
	
	if clientID == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
	}

	// Find the actual username that was generated during signup
	// For simplicity, we'll try to construct it - in production you might store this mapping
	// For now, we'll need to get this from somewhere else or handle it differently
	
	// Calculate SECRET_HASH if client secret is configured
	var secretHash *string
	if clientSecret != "" {
		hash := calculateSecretHash(req.Username, clientID, clientSecret)
		secretHash = aws.String(hash)
	}

	// Prepare ConfirmSignUp input
	confirmInput := &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         aws.String(clientID),
		Username:         aws.String(req.Username),
		ConfirmationCode: aws.String(req.Code),
		SecretHash:       secretHash,
	}

	// Log the request parameters for debugging
	log.Printf("Attempting verification for user: %s", req.Username)

	// Call Cognito ConfirmSignUp
	_, err := cognitoClient.ConfirmSignUp(c.Request().Context(), confirmInput)
	if err != nil {
		// Log the error for debugging
		log.Printf("Cognito ConfirmSignUp error: %v", err)
		
		// Check for specific error types with improved UX messaging
		if strings.Contains(err.Error(), "CodeMismatchException") {
			return echo.NewHTTPError(http.StatusBadRequest, "認証コードが正しくありません。入力したコードをご確認いただくか、新しいコードを再送してください。")
		}
		if strings.Contains(err.Error(), "ExpiredCodeException") {
			return echo.NewHTTPError(http.StatusBadRequest, "認証コードの有効期限が切れています。下の「認証コードを再送する」ボタンから新しいコードを取得してください。")
		}
		if strings.Contains(err.Error(), "AliasExistsException") {
			return echo.NewHTTPError(http.StatusBadRequest, "このメールアドレスは既に別のアカウントで使用されています。既存のアカウントでログインするか、別のメールアドレスで新規登録してください。")
		}
		if strings.Contains(err.Error(), "UserNotFoundException") {
			return echo.NewHTTPError(http.StatusBadRequest, "ユーザーが見つかりません。ユーザー名を正しく入力しているかご確認ください。")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("認証に失敗しました: %v", err))
	}

	// Log successful verification
	log.Printf("User verification successful for: %s", req.Username)

	// Return success response
	return c.JSON(http.StatusOK, map[string]any{
		"message": "認証が完了しました。ログインページに移動します。",
	})
}

func ResendCodeHandler(c echo.Context) error {
	// Parse request body
	var req ResendCodeRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate input
	if req.Username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	// Get environment variables
	clientID := os.Getenv("COGNITO_APP_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_APP_CLIENT_SECRET")
	
	if clientID == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
	}

	// Calculate SECRET_HASH if client secret is configured
	var secretHash *string
	if clientSecret != "" {
		hash := calculateSecretHash(req.Username, clientID, clientSecret)
		secretHash = aws.String(hash)
	}

	// Prepare ResendConfirmationCode input
	resendInput := &cognitoidentityprovider.ResendConfirmationCodeInput{
		ClientId:   aws.String(clientID),
		Username:   aws.String(req.Username),
		SecretHash: secretHash,
	}

	// Log the request parameters for debugging
	log.Printf("Attempting to resend confirmation code for user: %s", req.Username)

	// Call Cognito ResendConfirmationCode
	_, err := cognitoClient.ResendConfirmationCode(c.Request().Context(), resendInput)
	if err != nil {
		// Log the error for debugging
		log.Printf("Cognito ResendConfirmationCode error: %v", err)
		
		// Check for specific error types with improved UX messaging
		if strings.Contains(err.Error(), "UserNotFoundException") {
			return echo.NewHTTPError(http.StatusBadRequest, "そのユーザー名は存在しません。ユーザー名を正しく入力しているかご確認ください。")
		}
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return echo.NewHTTPError(http.StatusBadRequest, "入力内容に誤りがあります。ユーザー名を正しく入力してください。")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("コードの再送に失敗しました: %v", err))
	}

	// Log successful resend
	log.Printf("Confirmation code resent successfully for user: %s", req.Username)

	// Return success response
	return c.JSON(http.StatusOK, map[string]any{
		"message": "新しい認証コードを送信しました。",
	})
}

func GetUsageDetailsHandler(c echo.Context) error {
	// Get subscription ID from URL parameter
	subscriptionID := c.Param("id")
	if subscriptionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Subscription ID is required")
	}

	// Validate that subscription ID is a valid number
	subscriptionIDInt, err := strconv.Atoi(subscriptionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid subscription ID")
	}

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(*middleware.CognitoJWTClaims); ok {
		userID = userClaims.Subject
	}

	// Verify subscription belongs to user
	subscription, err := database.GetSubscriptionByID(subscriptionID, userID)
	if err != nil {
		log.Printf("Error fetching subscription for verification: %v", err)
		return echo.NewHTTPError(http.StatusNotFound, "Subscription not found")
	}
	if subscription == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Subscription not found")
	}

	// Get all usage logs for this subscription
	usageLogs, err := database.GetUsageLogsBySubscriptionID(subscriptionIDInt, userID)
	if err != nil {
		log.Printf("Error fetching usage logs: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch usage logs")
	}

	// Calculate statistics
	response := model.UsageDetailsResponse{
		UsageLogs: usageLogs,
	}

	// Calculate monthly stats
	monthlyMap := make(map[string]int)
	weekdayMap := make(map[string]int)
	now := time.Now()
	lastMonth := now.AddDate(0, -1, 0)
	thisMonthCount := 0
	lastMonthCount := 0

	for _, log := range usageLogs {
		// Monthly stats
		monthKey := log.CreatedAt.Format("2006-01")
		monthlyMap[monthKey]++

		// Weekday stats
		weekday := log.CreatedAt.Weekday().String()
		weekdayMap[weekday]++

		// This month vs last month comparison
		if log.CreatedAt.Year() == now.Year() && log.CreatedAt.Month() == now.Month() {
			thisMonthCount++
		} else if log.CreatedAt.Year() == lastMonth.Year() && log.CreatedAt.Month() == lastMonth.Month() {
			lastMonthCount++
		}
	}

	// Convert monthly map to sorted slice
	var monthlyStats []model.MonthlyUsageStat
	for month, count := range monthlyMap {
		monthlyStats = append(monthlyStats, model.MonthlyUsageStat{
			Month: month,
			Count: count,
		})
	}
	// Sort by month
	sort.Slice(monthlyStats, func(i, j int) bool {
		return monthlyStats[i].Month < monthlyStats[j].Month
	})
	response.MonthlyStats = monthlyStats

	// Convert weekday map to slice with proper order
	weekdays := []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
	weekdaysJP := []string{"月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日", "日曜日"}
	var weekdayStats []model.WeekdayUsageStat
	maxWeekdayCount := 0
	mostPopularWeekday := ""

	for i, weekday := range weekdays {
		count := weekdayMap[weekday]
		weekdayStats = append(weekdayStats, model.WeekdayUsageStat{
			Weekday: weekdaysJP[i], // Use Japanese weekday name
			Count:   count,
		})
		if count > maxWeekdayCount {
			maxWeekdayCount = count
			mostPopularWeekday = weekdaysJP[i]
		}
	}
	response.WeekdayStats = weekdayStats
	response.MostPopularWeekday = mostPopularWeekday

	// Set month comparison stats
	response.ThisMonthCount = thisMonthCount
	response.LastMonthCount = lastMonthCount
	
	// Calculate percentage change
	if lastMonthCount > 0 {
		response.MonthComparison = float64(thisMonthCount-lastMonthCount) / float64(lastMonthCount) * 100
	} else if thisMonthCount > 0 {
		response.MonthComparison = 100 // 100% increase if no usage last month
	} else {
		response.MonthComparison = 0
	}

	return c.JSON(http.StatusOK, response)
}