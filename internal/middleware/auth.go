package middleware

import (
	"context"
	"crypto/rsa"
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

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
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

var (
	jwksCache     *JWKSResponse
	jwksCacheTime time.Time
	cacheDuration = 1 * time.Hour
)

func CognitoAuthMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get environment variables
			userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
			region := os.Getenv("AWS_REGION")

			if userPoolID == "" || region == "" {
				return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
			}

			// Extract token from Authorization header or cookie
			var tokenString string
			
			// Try Authorization header first
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader != "" {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
				if tokenString == authHeader {
					// Redirect to login for invalid authorization header format
					return c.Redirect(http.StatusFound, "/login")
				}
			} else {
				// Try cookie if no Authorization header
				cookie, err := c.Cookie("access_token")
				if err != nil {
					// Redirect to login if no token is found
					return c.Redirect(http.StatusFound, "/login")
				}
				tokenString = cookie.Value
			}

			// Verify token
			token, err := verifyToken(tokenString, userPoolID, region)
			if err != nil {
				// Redirect to login if token verification fails
				return c.Redirect(http.StatusFound, "/login")
			}

			// Store claims in context
			c.Set("user", token.Claims)
			
			// Debug log to check claims
			if cognitoClaims, ok := token.Claims.(*CognitoJWTClaims); ok {
				log.Printf("CognitoAuthMiddleware: Token claims - Subject: %s, ClientID: %s, TokenUse: %s", 
					cognitoClaims.Subject, cognitoClaims.ClientID, cognitoClaims.TokenUse)
			}

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