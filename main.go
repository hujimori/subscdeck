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
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

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

var (
	jwksCache     *JWKSResponse
	jwksCacheTime time.Time
	cacheDuration = 1 * time.Hour
	cognitoClient *cognitoidentityprovider.Client
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

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(e.Start(":" + port))
}

func publicHandler(c echo.Context) error {
	html := `<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubsCDeck - Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .login-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #0056b3;
        }
        button:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }
        .error {
            color: #dc3545;
            margin-top: 10px;
            padding: 10px;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            display: none;
        }
        .success {
            color: #155724;
            margin-top: 10px;
            padding: 10px;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>SubsCDeck ログイン</h1>
        <div id="protectedContent" style="display: none; margin-bottom: 20px; padding: 15px; background-color: #e8f5e8; border: 1px solid #4caf50; border-radius: 4px; color: #2e7d32;">
            <strong>Protected Page Response:</strong>
            <div id="protectedResponse"></div>
        </div>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">ユーザー名:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">パスワード:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" id="loginBtn">ログイン</button>
        </form>
        <div id="errorMessage" class="error"></div>
        <div id="successMessage" class="success"></div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const loginBtn = document.getElementById('loginBtn');
            const errorMessage = document.getElementById('errorMessage');
            const successMessage = document.getElementById('successMessage');
            
            // Hide previous messages
            errorMessage.style.display = 'none';
            successMessage.style.display = 'none';
            
            // Disable button during request
            loginBtn.disabled = true;
            loginBtn.textContent = 'ログイン中...';
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Success - display JWT token in console and show success message
                    console.log('ログイン成功！');
                    console.log('JWT Access Token:', data.access_token);
                    console.log('JWT ID Token:', data.id_token);
                    console.log('Refresh Token:', data.refresh_token);
                    console.log('Expires In:', data.expires_in, 'seconds');
                    console.log('Token Type:', data.token_type);
                    
                    successMessage.textContent = 'ログインに成功しました！JWTトークンがブラウザのコンソールに出力され、保護されたページにアクセスしています...';
                    successMessage.style.display = 'block';
                    
                    // Clear form
                    document.getElementById('loginForm').reset();
                    
                    // Call protected endpoint with the access token
                    await callProtectedEndpoint(data.access_token);
                } else {
                    // Error
                    errorMessage.textContent = data.message || 'ログインに失敗しました。';
                    errorMessage.style.display = 'block';
                }
            } catch (error) {
                console.error('Error:', error);
                errorMessage.textContent = 'ネットワークエラーが発生しました。';
                errorMessage.style.display = 'block';
            } finally {
                // Re-enable button
                loginBtn.disabled = false;
                loginBtn.textContent = 'ログイン';
            }
        });
        
        // Function to call protected endpoint with JWT token
        async function callProtectedEndpoint(accessToken) {
            const protectedContent = document.getElementById('protectedContent');
            const protectedResponse = document.getElementById('protectedResponse');
            
            try {
                console.log('Calling protected endpoint with token:', accessToken);
                
                const response = await fetch('/protected', {
                    method: 'GET',
                    headers: {
                        'Authorization': 'Bearer ' + accessToken
                    }
                });
                
                if (response.ok) {
                    const responseText = await response.text();
                    console.log('Protected endpoint response:', responseText);
                    
                    // Display the response in the div
                    protectedResponse.textContent = responseText;
                    protectedContent.style.display = 'block';
                    
                    // Update success message
                    const successMessage = document.getElementById('successMessage');
                    successMessage.textContent = 'ログイン成功！JWTトークンでの認証も成功し、保護されたページにアクセスできました。';
                } else {
                    console.error('Protected endpoint failed:', response.status, response.statusText);
                    protectedResponse.textContent = 'Error: ' + response.status + ' ' + response.statusText;
                    protectedContent.style.display = 'block';
                }
            } catch (error) {
                console.error('Error calling protected endpoint:', error);
                protectedResponse.textContent = 'Network error occurred while calling protected endpoint';
                protectedContent.style.display = 'block';
            }
        }
    </script>
</body>
</html>`
	return c.HTML(http.StatusOK, html)
}

func protectedHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Protected Page")
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