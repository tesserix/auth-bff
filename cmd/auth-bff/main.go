package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/tesserix/auth-bff/internal/appregistry"
	"github.com/tesserix/auth-bff/internal/clients"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/events"
	"github.com/tesserix/auth-bff/internal/handlers"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/oidc"
	"github.com/tesserix/auth-bff/internal/session"
	"github.com/tesserix/go-shared/logger"
	goshmw "github.com/tesserix/go-shared/middleware"
)

func main() {
	// Load .env in development
	_ = godotenv.Load()

	// Logger (go-shared structured logger with PII sanitization)
	logCfg := logger.DefaultConfig("auth-bff")
	if os.Getenv("APP_ENV") == "development" {
		logCfg.Level = logger.LevelDebug
	}
	appLogger := logger.New(logCfg)
	slog.SetDefault(appLogger.Logger)

	// Config
	cfg, err := config.Load()
	if err != nil {
		appLogger.Error("load config", "error", err)
		os.Exit(1)
	}

	appLogger.Info("starting auth-bff",
		"env", cfg.Environment,
		"port", cfg.Port,
	)

	// Redis
	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		appLogger.Error("parse redis url", "error", err)
		os.Exit(1)
	}
	redisClient := redis.NewClient(redisOpts)
	defer redisClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		appLogger.Error("redis connection failed", "error", err)
		os.Exit(1)
	}
	appLogger.Info("redis connected")

	// Session store
	store := session.NewRedisStore(redisClient)

	// App registry
	registry := appregistry.New(cfg.Apps)

	// OIDC provider manager
	oidcCtx, oidcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer oidcCancel()
	oidcMgr, err := oidc.NewManager(oidcCtx, cfg)
	if err != nil {
		appLogger.Error("oidc manager init failed", "error", err)
		os.Exit(1)
	}
	appLogger.Info("oidc providers initialized")

	// Clients
	tenantClient := clients.NewTenantClient(cfg.TenantServiceURL)
	verificationClient := clients.NewVerificationClient(cfg.VerificationServiceURL, cfg.VerificationAPIKey)

	// Events publisher
	eventPublisher := events.NewPublisher(cfg.NATSURL, appLogger)
	defer eventPublisher.Close()

	// Gin router
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	router.Use(goshmw.Recovery()) // go-shared structured panic recovery

	// Global middleware
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitRPM)
	router.Use(rateLimiter.Middleware())
	router.Use(corsMiddleware(cfg))
	router.Use(goshmw.SecurityHeaders())          // go-shared security headers (CSP, HSTS, Permissions-Policy, etc.)
	router.Use(goshmw.RequestIDMiddleware())       // go-shared UUID-based request IDs
	router.Use(appLogger.GinMiddleware())          // go-shared request/response logging
	router.Use(middleware.AppResolver(registry))
	router.Use(middleware.SessionExtractor(store))

	// Health endpoints (no auth)
	healthHandler := handlers.NewHealthHandler(store)
	healthHandler.RegisterRoutes(router)

	// Auth routes group
	authGroup := router.Group("")

	// OIDC auth
	authHandler := handlers.NewAuthHandler(cfg, store, oidcMgr, appLogger)
	authHandler.RegisterRoutes(authGroup)

	// Direct auth
	directAuthHandler := handlers.NewDirectAuthHandler(cfg, store, tenantClient, appLogger)
	directAuthHandler.RegisterRoutes(authGroup)

	// TOTP
	totpHandler := handlers.NewTOTPHandler(cfg, store, tenantClient, appLogger)
	totpHandler.RegisterRoutes(authGroup)

	// OTP
	otpHandler := handlers.NewOTPHandler(store, verificationClient, appLogger)
	otpHandler.RegisterRoutes(authGroup)

	// Passkey
	passkeyHandler := handlers.NewPasskeyHandler(cfg, store, tenantClient, appLogger)
	passkeyHandler.RegisterRoutes(authGroup)

	// API proxy
	proxyHandler := handlers.NewProxyHandler(cfg, store, oidcMgr, tenantClient, appLogger)
	proxyHandler.RegisterRoutes(router)

	// Internal endpoints
	internalHandler := handlers.NewInternalHandler(cfg, store, appLogger)
	internalHandler.RegisterRoutes(router)

	// Keep event publisher reference for use in handlers
	_ = eventPublisher

	// HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	appLogger.Info("auth-bff started", "addr", srv.Addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		appLogger.Error("server shutdown error", "error", err)
	}

	appLogger.Info("auth-bff stopped")
}

// corsMiddleware provides dynamic CORS based on app config.
func corsMiddleware(cfg *config.Config) gin.HandlerFunc {
	origins := cfg.AllAllowedOrigins()

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		allowed := false
		for _, o := range origins {
			if matchOrigin(origin, o) {
				c.Header("Access-Control-Allow-Origin", origin)
				allowed = true
				break
			}
		}

		if !allowed {
			c.Next()
			return
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-Tenant-ID, X-Tenant-Slug, X-Device-Type, X-Request-ID")
		c.Header("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Request-ID")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// matchOrigin checks if an origin matches a pattern (supports * prefix wildcards).
func matchOrigin(origin, pattern string) bool {
	if pattern == origin {
		return true
	}
	if len(pattern) > 0 && pattern[0] == '*' {
		return false
	}
	// Handle https://*.domain pattern
	if idx := len("https://"); len(pattern) > idx && pattern[idx] == '*' {
		suffix := pattern[idx+1:] // e.g. ".tesserix.app"
		if len(origin) > idx {
			originHost := origin[idx:] // e.g. "demo.tesserix.app"
			if len(originHost) > len(suffix) && originHost[len(originHost)-len(suffix):] == suffix {
				return true
			}
		}
	}
	return false
}
