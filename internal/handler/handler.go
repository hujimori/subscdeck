package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

var (
	cognitoClient *cognitoidentityprovider.Client
	// ダミーのサブスクリプションデータ
	subscriptions = []model.Subscription{
		{ID: "1", ServiceName: "Netflix", Price: 1490, CreatedAt: time.Now().AddDate(0, -3, 0)},
		{ID: "2", ServiceName: "AWS", Price: 5000, CreatedAt: time.Now().AddDate(0, -6, 0)},
		{ID: "3", ServiceName: "Spotify", Price: 980, CreatedAt: time.Now().AddDate(0, -2, 0)},
		{ID: "4", ServiceName: "Adobe Creative Cloud", Price: 6480, CreatedAt: time.Now().AddDate(0, -1, 0)},
		{ID: "5", ServiceName: "GitHub Pro", Price: 1100, CreatedAt: time.Now().AddDate(0, -4, 0)},
	}
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
	tmpl, err := template.ParseFiles("web/template/dashboard.html")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load template")
	}
	return tmpl.Execute(c.Response(), nil)
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

	// Prepare response
	response := LoginResponse{
		AccessToken:  aws.ToString(result.AuthenticationResult.AccessToken),
		IDToken:      aws.ToString(result.AuthenticationResult.IdToken),
		RefreshToken: aws.ToString(result.AuthenticationResult.RefreshToken),
		ExpiresIn:    result.AuthenticationResult.ExpiresIn,
		TokenType:    aws.ToString(result.AuthenticationResult.TokenType),
	}

	return c.JSON(http.StatusOK, response)
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

	// Create new subscription (in a real app, this would save to database)
	newSub := model.Subscription{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		ServiceName: req.ServiceName,
		Price:       req.Price,
		CreatedAt:   time.Now(),
	}

	// Add to our in-memory list
	subscriptions = append([]model.Subscription{newSub}, subscriptions...)

	// Return the created subscription
	return c.JSON(http.StatusCreated, newSub)
}