package main

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"subscdeck/internal/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type CognitoJWTClaims struct {
	jwt.RegisteredClaims
	TokenUse string `json:"token_use"`
	ClientID string `json:"client_id"`
}

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
	jwksCache     *JWKSResponse
	jwksCacheTime time.Time
	cacheDuration = 1 * time.Hour
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

func main() {
	// Load .env file (try .env.local first, then .env)
	err := godotenv.Load(".env.local")
	if err != nil {
		err = godotenv.Load(".env")
		if err != nil {
			log.Printf("Warning: Error loading .env files: %v", err)
		}
	}

	// Check if COGNITO_USER_POOL_ID is loaded correctly
	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	fmt.Println("COGNITO_USER_POOL_ID:", userPoolID)

	// Initialize AWS Cognito client
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config: %v", err)
	}
	cognitoClient = cognitoidentityprovider.NewFromConfig(cfg)

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/", publicHandler)
	e.POST("/login", loginHandler)
	e.GET("/protected", protectedHandler, cognitoAuthMiddleware())
	e.GET("/dashboard", dashboardHandler)
	e.POST("/api/subscriptions", createSubscriptionHandler, cognitoAuthMiddleware())

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(e.Start(":" + port))
}

func publicHandler(c echo.Context) error {
	tmpl, err := template.ParseFiles("web/template/login.html")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load template")
	}
	return tmpl.Execute(c.Response(), nil)
}

func protectedHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Protected API endpoint - Authentication successful")
}

func dashboardHandler(c echo.Context) error {
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

func loginHandler(c echo.Context) error {
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

func cognitoAuthMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get environment variables
			userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
			region := os.Getenv("AWS_REGION")

			if userPoolID == "" || region == "" {
				return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
			}

			// Extract token from Authorization header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization header")
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header format")
			}

			// Verify token
			token, err := verifyToken(tokenString, userPoolID, region)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			// Store claims in context
			c.Set("user", token.Claims)

			return next(c)
		}
	}
}

func verifyToken(tokenString, userPoolID, region string) (*jwt.Token, error) {
	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &CognitoJWTClaims{}, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get kid from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid not found in token header")
		}

		// Get JWKS
		jwks, err := getJWKS(userPoolID, region)
		if err != nil {
			return nil, err
		}

		// Find the key with matching kid
		for _, key := range jwks.Keys {
			if key.Kid == kid {
				// Convert JWK to RSA public key
				pubKey, err := jwkToRSAPublicKey(&key)
				if err != nil {
					return nil, err
				}
				return pubKey, nil
			}
		}

		return nil, errors.New("unable to find matching key")
	})

	if err != nil {
		return nil, err
	}

	// Validate claims
	claims, ok := token.Claims.(*CognitoJWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Verify token use (should be "access" for API access)
	if claims.TokenUse != "access" {
		return nil, errors.New("token is not an access token")
	}

	// Verify issuer
	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)
	if claims.Issuer != expectedIssuer {
		return nil, errors.New("invalid issuer")
	}

	return token, nil
}

func getJWKS(userPoolID, region string) (*JWKSResponse, error) {
	// Check cache
	if jwksCache != nil && time.Since(jwksCacheTime) < cacheDuration {
		return jwksCache, nil
	}

	// Fetch JWKS from Cognito
	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: %s", resp.Status)
	}

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	// Update cache
	jwksCache = &jwks
	jwksCacheTime = time.Now()

	return &jwks, nil
}

func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	// Decode n and e from base64
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	// Convert e to int
	var eInt int
	for _, b := range eBytes {
		eInt = eInt*256 + int(b)
	}

	// Create public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	return pubKey, nil
}

func createSubscriptionHandler(c echo.Context) error {
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