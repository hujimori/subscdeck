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
	"strconv"
	"strings"
	"time"

	"subscdeck/internal/database"
	"subscdeck/internal/model"

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
		if userClaims, ok := userContext.(map[string]interface{}); ok {
			if sub, exists := userClaims["sub"]; exists {
				if subStr, ok := sub.(string); ok {
					userID = subStr
				}
			}
		}
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
		
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "NotAuthorizedException") {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid username or password")
		}
		if strings.Contains(err.Error(), "UserNotFoundException") {
			return echo.NewHTTPError(http.StatusUnauthorized, "User not found")
		}
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid request parameters")
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
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
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
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
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
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
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
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
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
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
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
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
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
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
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

	// Get user info from JWT context (set by auth middleware)
	userContext := c.Get("user")
	if userContext == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
	}
	
	// Extract user ID from JWT claims
	userID := "unknown_user" // Default fallback
	if userClaims, ok := userContext.(map[string]interface{}); ok {
		if sub, exists := userClaims["sub"]; exists {
			if subStr, ok := sub.(string); ok {
				userID = subStr
			}
		}
	}

	// Get subscription information from database
	subscription, err := database.GetSubscriptionByID(subscriptionID, userID)
	if err != nil {
		log.Printf("Error fetching subscription for user %s: %v", userID, err)
		return echo.NewHTTPError(http.StatusNotFound, "Subscription not found")
	}

	// Calculate usage statistics for the last 3 months
	var usageStats []UsageStatResponse
	now := time.Now()
	
	for i := 2; i >= 0; i-- {
		targetDate := now.AddDate(0, -i, 0)
		year := targetDate.Year()
		month := int(targetDate.Month())
		
		// Get usage count for this month
		usageCount, err := database.GetMonthlyUsageCountByMonth(subscriptionIDInt, userID, year, month)
		if err != nil {
			log.Printf("Error fetching monthly usage count for subscription %s, year %d, month %d: %v", subscriptionID, year, month, err)
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
	if req.Username == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username and password are required")
	}

	// Get environment variables
	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	clientID := os.Getenv("COGNITO_APP_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_APP_CLIENT_SECRET")
	
	if userPoolID == "" || clientID == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
	}

	// Generate a unique username (UUID) since the user pool uses email alias
	// This prevents the "Username cannot be of email format" error
	uniqueUsername := fmt.Sprintf("user-%d-%s", time.Now().Unix(), req.Username[:3])
	
	// Calculate SECRET_HASH if client secret is configured
	var secretHash *string
	if clientSecret != "" {
		hash := calculateSecretHash(uniqueUsername, clientID, clientSecret)
		secretHash = aws.String(hash)
	}

	// Prepare SignUp input
	signUpInput := &cognitoidentityprovider.SignUpInput{
		ClientId:   aws.String(clientID),
		Username:   aws.String(uniqueUsername),
		Password:   aws.String(req.Password),
		SecretHash: secretHash,
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(req.Username),
			},
		},
	}

	// Log the request parameters for debugging
	log.Printf("Attempting signup for email: %s with username: %s", req.Username, uniqueUsername)
	log.Printf("Using User Pool ID: %s", userPoolID)
	log.Printf("Using Client ID: %s", clientID)

	// Call Cognito SignUp
	result, err := cognitoClient.SignUp(c.Request().Context(), signUpInput)
	if err != nil {
		// Log the error for debugging
		log.Printf("Cognito SignUp error: %v", err)
		
		// Check for specific error types
		if strings.Contains(err.Error(), "UsernameExistsException") {
			return echo.NewHTTPError(http.StatusBadRequest, "このメールアドレスは既に登録されています")
		}
		if strings.Contains(err.Error(), "InvalidPasswordException") {
			return echo.NewHTTPError(http.StatusBadRequest, "パスワードは8文字以上で、大文字・小文字・数字を含む必要があります")
		}
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return echo.NewHTTPError(http.StatusBadRequest, "入力内容に誤りがあります")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("アカウント作成に失敗しました: %v", err))
	}

	// Log successful signup
	log.Printf("User signup successful for: %s, UserConfirmed: %v", req.Username, result.UserConfirmed)

	// Return redirect to verify page
	return c.JSON(http.StatusOK, map[string]interface{}{
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
		
		// Check for specific error types
		if strings.Contains(err.Error(), "CodeMismatchException") {
			return echo.NewHTTPError(http.StatusBadRequest, "認証コードが正しくありません")
		}
		if strings.Contains(err.Error(), "ExpiredCodeException") {
			return echo.NewHTTPError(http.StatusBadRequest, "認証コードの有効期限が切れています")
		}
		if strings.Contains(err.Error(), "UserNotFoundException") {
			return echo.NewHTTPError(http.StatusBadRequest, "ユーザーが見つかりません")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("認証に失敗しました: %v", err))
	}

	// Log successful verification
	log.Printf("User verification successful for: %s", req.Username)

	// Return success response
	return c.JSON(http.StatusOK, map[string]interface{}{
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
		
		// Check for specific error types
		if strings.Contains(err.Error(), "UserNotFoundException") {
			return echo.NewHTTPError(http.StatusBadRequest, "ユーザーが見つかりません")
		}
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return echo.NewHTTPError(http.StatusBadRequest, "無効なパラメータです")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("コードの再送に失敗しました: %v", err))
	}

	// Log successful resend
	log.Printf("Confirmation code resent successfully for user: %s", req.Username)

	// Return success response
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "新しい認証コードを送信しました。",
	})
}