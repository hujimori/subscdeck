package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"subscdeck/internal/handler"
	"subscdeck/internal/middleware"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
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
	cognitoClient := cognitoidentityprovider.NewFromConfig(cfg)
	
	// Set Cognito client for handlers
	handler.SetCognitoClient(cognitoClient)

	e := echo.New()

	// Middleware
	e.Use(echomiddleware.Logger())
	e.Use(echomiddleware.Recover())

	// Routes
	e.GET("/", handler.PublicHandler)
	e.POST("/login", handler.LoginHandler)
	e.GET("/protected", handler.ProtectedHandler, middleware.CognitoAuthMiddleware())
	e.GET("/dashboard", handler.DashboardHandler)
	e.POST("/api/subscriptions", handler.CreateSubscriptionHandler, middleware.CognitoAuthMiddleware())

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(e.Start(":" + port))
}