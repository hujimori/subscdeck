package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"subscdeck/internal/database"
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

	// Initialize SQLite database
	err = database.InitDB("subscdeck.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

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
	e.GET("/dashboard", handler.DashboardHandler, middleware.CognitoAuthMiddleware())
	e.GET("/api/subscriptions", handler.GetSubscriptionsHandler, middleware.CognitoAuthMiddleware())
	e.POST("/api/subscriptions", handler.CreateSubscriptionHandler, middleware.CognitoAuthMiddleware())
	e.PUT("/api/subscriptions/:id", handler.UpdateSubscriptionHandler, middleware.CognitoAuthMiddleware())
	e.POST("/subscriptions/delete", handler.DeleteSubscriptionHandler, middleware.CognitoAuthMiddleware())
	e.GET("/subscriptions/edit", handler.EditSubscriptionHandler, middleware.CognitoAuthMiddleware())
	e.POST("/subscriptions/update", handler.UpdateSubscriptionFormHandler, middleware.CognitoAuthMiddleware())
	e.POST("/api/usage_logs", handler.CreateUsageLogHandler, middleware.CognitoAuthMiddleware())
	e.GET("/api/subscriptions/:id/usage_stats", handler.GetUsageStatsHandler, middleware.CognitoAuthMiddleware())
	e.POST("/logout", handler.LogoutHandler)
	e.GET("/signup", handler.SignupPageHandler)
	e.POST("/signup", handler.SignupHandler)
	e.GET("/verify", handler.VerifyPageHandler)
	e.POST("/verify", handler.VerifyHandler)
	e.POST("/resend-code", handler.ResendCodeHandler)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(e.Start(":" + port))
}