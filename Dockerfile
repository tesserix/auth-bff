FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git for module downloads
RUN apk add --no-cache git

# Copy dependency files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /auth-bff ./cmd/auth-bff

# Production image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget tzdata

# Non-root user
RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -D appuser

COPY --from=builder /auth-bff /auth-bff

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/auth-bff"]
