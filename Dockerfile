# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite

# Create non-root user
RUN addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Create data directory for SQLite database
RUN mkdir -p /data && chown appuser:appgroup /data

# Copy the binary from builder
COPY --from=builder /app/main .

# Copy web templates
COPY --from=builder /app/web ./web

# Set ownership
RUN chown -R appuser:appgroup /app

# Use non-root user
USER appuser

# Expose port (default 8080)
EXPOSE 8080

# Volume for SQLite database
VOLUME ["/data"]

# Run the application
CMD ["./main"]