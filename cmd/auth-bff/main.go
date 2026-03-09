package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/tesserix/auth-bff/internal/appregistry"
	"github.com/tesserix/auth-bff/internal/clients"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/events"
	"github.com/tesserix/auth-bff/internal/gip"
	"github.com/tesserix/auth-bff/internal/handlers"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
	"github.com/tesserix/go-shared/logger"
	goshmw "github.com/tesserix/go-shared/middleware"
)

func main() {
	_ = godotenv.Load()

	// Logger
	logCfg := logger.DefaultConfig("auth-bff")
	if os.Getenv("APP_ENV") == "development" {
		logCfg.Level = logger.LevelDebug
	}
	appLogger := logger.New(logCfg)
	slog.SetDefault(appLogger.Logger)

	// Config
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}
	slog.Info("starting auth-bff", "env", cfg.Environment, "port", cfg.Port)

	// Google Identity Platform client
	gipCtx, gipCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gipCancel()
	gipClient, err := gip.NewClient(gipCtx, cfg)
	if err != nil {
		slog.Error("gip client init failed", "error", err)
		os.Exit(1)
	}
	slog.Info("gip providers initialized")

	// Session stores
	cookieStore := session.NewCookieStore(cfg.CookieEncryptionKey, cfg.SessionMaxAge, cfg.CookieSecure)
	ephemeralStore := session.NewEphemeralStore()

	// Service clients (auto-authenticated via OIDC on Cloud Run)
	tenantClient, err := clients.NewTenantClient(cfg.TenantServiceURL)
	if err != nil {
		slog.Error("create tenant client", "error", err)
		os.Exit(1)
	}

	// Events publisher (Pub/Sub)
	eventPublisher := events.NewPublisher(context.Background(), cfg.GCPProjectID)
	defer eventPublisher.Close()

	// App registry
	registry := appregistry.New(cfg.Apps)

	// Router
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	router.Use(goshmw.Recovery())

	// Global middleware
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitRPM)
	router.Use(rateLimiter.Middleware())
	router.Use(corsMiddleware(cfg))
	router.Use(goshmw.SecurityHeaders())
	router.Use(goshmw.RequestIDMiddleware())
	router.Use(appLogger.GinMiddleware())
	router.Use(middleware.AppResolver(registry))
	router.Use(middleware.SessionExtractor(cookieStore))

	// Health (no auth)
	healthHandler := handlers.NewHealthHandler()
	healthHandler.RegisterRoutes(router)

	// Auth routes
	authGroup := router.Group("")
	authHandler := handlers.NewAuthHandler(cfg, gipClient, cookieStore, ephemeralStore, eventPublisher)
	authHandler.RegisterRoutes(authGroup)

	// MFA routes
	mfaHandler := handlers.NewMFAHandler(cfg, cookieStore, ephemeralStore, tenantClient)
	mfaHandler.RegisterRoutes(authGroup)

	// Internal endpoints (service-to-service)
	internalHandler := handlers.NewInternalHandler(cfg, gipClient, cookieStore)
	internalHandler.RegisterRoutes(router)

	// HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	slog.Info("auth-bff started", "addr", srv.Addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}
	slog.Info("auth-bff stopped")
}

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
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-Request-ID")
		c.Header("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Request-ID")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func matchOrigin(origin, pattern string) bool {
	if pattern == origin {
		return true
	}
	idx := strings.IndexByte(pattern, '*')
	if idx < 0 {
		return false
	}
	prefix := pattern[:idx]
	suffix := pattern[idx+1:]
	if !strings.HasPrefix(origin, prefix) {
		return false
	}
	if !strings.HasSuffix(origin, suffix) {
		return false
	}
	return len(origin) >= len(prefix)+len(suffix)
}
