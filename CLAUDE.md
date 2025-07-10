# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

subscdeck is a Go web server using Echo v4 framework with AWS Cognito JWT authentication.

## Technology Stack

- **Language**: Go 1.21+
- **Web Framework**: Echo v4
- **Authentication**: AWS Cognito (JWT with JWKS validation)
- **AWS SDK**: AWS SDK for Go v2

## Common Commands

```bash
# Install dependencies
go mod download

# Run the server
go run main.go

# Build the application
go build -o subscdeck main.go

# Run with environment variables
COGNITO_USER_POOL_ID=xxx COGNITO_APP_CLIENT_ID=xxx AWS_REGION=ap-northeast-1 go run main.go
```

## Architecture

The application implements:
- Public endpoint at `/` - accessible without authentication
- Login endpoint at `/login` - accepts username/password and returns JWT tokens
- Protected endpoint at `/protected` - requires valid Cognito JWT access token
- Custom middleware for JWT validation using JWKS from Cognito
- JWKS caching (1 hour) to reduce API calls to Cognito

## Key Implementation Details

- Uses AWS SDK v2 for Cognito authentication (InitiateAuth API)
- JWT validation fetches public keys from Cognito's JWKS endpoint
- Only accepts access tokens (not ID tokens) for API access
- Validates token issuer against expected Cognito user pool
- Uses environment variables for configuration (COGNITO_USER_POOL_ID, COGNITO_APP_CLIENT_ID, AWS_REGION)