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

type Subscription struct {
	ID          string    `json:"id"`
	ServiceName string    `json:"service_name"`
	Price       int       `json:"price"`
	CreatedAt   time.Time `json:"created_at"`
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
	subscriptions = []Subscription{
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
                    
                    // Save access token to localStorage
                    localStorage.setItem('accessToken', data.access_token);
                    console.log('トークンを保存しました');
                    
                    successMessage.textContent = 'ログインに成功しました！ダッシュボードに移動します...';
                    successMessage.style.display = 'block';
                    
                    // Clear form
                    document.getElementById('loginForm').reset();
                    
                    // Redirect to dashboard after a short delay
                    setTimeout(() => {
                        window.location.href = '/dashboard';
                    }, 1000);
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
    </script>
</body>
</html>`
	return c.HTML(http.StatusOK, html)
}

func protectedHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Protected API endpoint - Authentication successful")
}

func dashboardHandler(c echo.Context) error {
	html := `<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubscDeck - サブスクリプション管理</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 40px;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .form-section {
            margin-bottom: 40px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 8px;
        }
        .form-section h2 {
            margin-top: 0;
            color: #555;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            padding: 12px 24px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #218838;
        }
        .subscription-list {
            margin-top: 30px;
        }
        .subscription-list h2 {
            color: #333;
            margin-bottom: 20px;
        }
        .subscription-item {
            padding: 15px;
            margin-bottom: 10px;
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .subscription-info {
            flex: 1;
        }
        .subscription-name {
            font-weight: bold;
            font-size: 18px;
            color: #333;
            margin-bottom: 5px;
        }
        .subscription-price {
            color: #dc3545;
            font-size: 20px;
            font-weight: bold;
        }
        .subscription-date {
            color: #6c757d;
            font-size: 14px;
        }
        .total-section {
            margin-top: 20px;
            padding: 20px;
            background-color: #e7f3ff;
            border: 2px solid #007bff;
            border-radius: 8px;
            text-align: right;
        }
        .total-label {
            font-size: 18px;
            color: #333;
            margin-right: 10px;
        }
        .total-amount {
            font-size: 24px;
            font-weight: bold;
            color: #dc3545;
        }
    </style>
</head>
<body>
    <h1>SubscDeck</h1>
    <div class="container">
        <div class="form-section">
            <h2>新規サブスクリプション登録</h2>
            <form id="subscriptionForm">
                <div class="form-group">
                    <label for="service_name">サービス名:</label>
                    <input type="text" id="service_name" name="service_name" required placeholder="例: Netflix, Spotify">
                </div>
                <div class="form-group">
                    <label for="price">月額料金 (円):</label>
                    <input type="number" id="price" name="price" required placeholder="例: 1490">
                </div>
                <button type="submit">登録</button>
            </form>
        </div>

        <div class="subscription-list">
            <h2>登録済みサブスクリプション</h2>
            <div id="subscriptionList"></div>
            <div class="total-section">
                <span class="total-label">月額合計:</span>
                <span class="total-amount" id="totalAmount">¥0</span>
            </div>
        </div>
    </div>

    <script>
        // トークンチェック - ログインしていない場合はリダイレクト
        const token = localStorage.getItem('accessToken');
        if (!token) {
            window.location.href = '/';
        }

        // ダミーデータのサブスクリプション
        const subscriptions = [
            {id: "1", service_name: "Netflix", price: 1490, created_at: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)},
            {id: "2", service_name: "AWS", price: 5000, created_at: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000)},
            {id: "3", service_name: "Spotify", price: 980, created_at: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000)},
            {id: "4", service_name: "Adobe Creative Cloud", price: 6480, created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)},
            {id: "5", service_name: "GitHub Pro", price: 1100, created_at: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000)}
        ];

        // サブスクリプション一覧を表示
        function displaySubscriptions() {
            const listContainer = document.getElementById('subscriptionList');
            listContainer.innerHTML = '';
            let total = 0;

            subscriptions.forEach(sub => {
                const item = document.createElement('div');
                item.className = 'subscription-item';
                
                const createdDate = new Date(sub.created_at).toLocaleDateString('ja-JP');
                
                item.innerHTML = ` + "`" + `
                    <div class="subscription-info">
                        <div class="subscription-name">${sub.service_name}</div>
                        <div class="subscription-date">登録日: ${createdDate}</div>
                    </div>
                    <div class="subscription-price">¥${sub.price.toLocaleString()}</div>
                ` + "`" + `;
                
                listContainer.appendChild(item);
                total += sub.price;
            });

            // 合計金額を更新
            document.getElementById('totalAmount').textContent = '¥' + total.toLocaleString();
        }

        // フォーム送信処理
        document.getElementById('subscriptionForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const serviceName = document.getElementById('service_name').value;
            const price = parseInt(document.getElementById('price').value);
            const token = localStorage.getItem('accessToken');
            
            if (!token) {
                alert('ログインが必要です');
                window.location.href = '/';
                return;
            }
            
            try {
                const response = await fetch('/api/subscriptions', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify({
                        service_name: serviceName,
                        price: price
                    })
                });
                
                if (response.ok) {
                    const newSub = await response.json();
                    
                    // 新しいサブスクリプションを追加
                    subscriptions.unshift({
                        id: newSub.id,
                        service_name: newSub.service_name,
                        price: newSub.price,
                        created_at: new Date(newSub.created_at)
                    });
                    
                    // フォームをクリア
                    document.getElementById('subscriptionForm').reset();
                    
                    // 一覧を再表示
                    displaySubscriptions();
                } else if (response.status === 401) {
                    alert('認証エラー: ログインし直してください');
                    localStorage.removeItem('accessToken');
                    window.location.href = '/';
                } else {
                    const error = await response.json();
                    alert('エラー: ' + (error.message || 'サブスクリプションの登録に失敗しました'));
                }
            } catch (error) {
                console.error('Error:', error);
                alert('ネットワークエラーが発生しました');
            }
        });

        // 初回表示
        displaySubscriptions();
    </script>
</body>
</html>`
	return c.HTML(http.StatusOK, html)
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
	newSub := Subscription{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		ServiceName: req.ServiceName,
		Price:       req.Price,
		CreatedAt:   time.Now(),
	}

	// Add to our in-memory list
	subscriptions = append([]Subscription{newSub}, subscriptions...)

	// Return the created subscription
	return c.JSON(http.StatusCreated, newSub)
}