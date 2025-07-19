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
	"strings"

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
}

type UpdateSubscriptionFormRequest struct {
	ID          string `form:"id"`
	ServiceName string `form:"service_name"`
	Price       int    `form:"price"`
}

type CreateUsageLogRequest struct {
	SubscriptionID int `json:"subscription_id"`
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
	// Get all subscriptions from database
	subscriptions, err := database.GetAllSubscriptions()
	if err != nil {
		log.Printf("Error fetching subscriptions: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch subscriptions")
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
	userContext := c.Get("user")
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
	// Get all subscriptions from database
	subscriptions, err := database.GetAllSubscriptions()
	if err != nil {
		log.Printf("Error fetching subscriptions: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch subscriptions")
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

	// Create new subscription in database
	newSub, err := database.CreateSubscription(req.ServiceName, req.Price)
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

	// Delete from database
	err := database.DeleteSubscription(req.ID)
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

	// Get subscription from database
	subscription, err := database.GetSubscriptionByID(req.ID)
	if err != nil {
		log.Printf("Error fetching subscription: %v", err)
		return echo.NewHTTPError(http.StatusNotFound, "Subscription not found")
	}

	// Check if user is logged in by checking if user context exists
	userContext := c.Get("user")
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

	// Update subscription in database
	updatedSub, err := database.UpdateSubscription(id, req.ServiceName, req.Price)
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

	// Update subscription in database
	_, err := database.UpdateSubscription(req.ID, req.ServiceName, req.Price)
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