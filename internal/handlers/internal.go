package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/gip"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

// slugPattern validates tenant slugs: lowercase alphanumeric + hyphens, 2-63 chars.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)

// isValidSlug checks that a tenant slug contains only safe characters.
func isValidSlug(slug string) bool {
	if len(slug) < 2 || len(slug) > 63 {
		return false
	}
	return slugPattern.MatchString(slug)
}

// InternalHandler handles service-to-service requests.
// Other services call these endpoints to verify tokens or exchange session data.
type InternalHandler struct {
	cfg       *config.Config
	gip       *gip.Client
	sessions  *session.CookieStore
	ephemeral *session.EphemeralStore
	// rateLimiter tracks calls per service key (simple in-memory counter)
	rateLimiter *rateLimiter
}

// rateLimiter provides simple per-key rate limiting for internal endpoints.
type rateLimiter struct {
	mu       sync.Mutex
	counters map[string]*rateCounter
}

type rateCounter struct {
	count    int
	windowAt time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{counters: make(map[string]*rateCounter)}
}

// allow checks if the key is within the rate limit (60 requests per minute).
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rc, ok := rl.counters[key]
	if !ok || now.Sub(rc.windowAt) > time.Minute {
		rl.counters[key] = &rateCounter{count: 1, windowAt: now}
		return true
	}
	rc.count++
	return rc.count <= 60
}

// NewInternalHandler creates a new InternalHandler.
func NewInternalHandler(cfg *config.Config, gipClient *gip.Client, sessions *session.CookieStore, ephemeral *session.EphemeralStore) *InternalHandler {
	return &InternalHandler{cfg: cfg, gip: gipClient, sessions: sessions, ephemeral: ephemeral, rateLimiter: newRateLimiter()}
}

// RegisterRoutes registers internal endpoints.
func (h *InternalHandler) RegisterRoutes(r *gin.Engine) {
	internal := r.Group("/internal")
	internal.Use(h.requireServiceKey())
	internal.Use(h.rateLimit())

	internal.POST("/verify-token", h.VerifyToken)
	internal.POST("/session-exchange", h.SessionExchange)
	internal.POST("/create-exchange-code", h.CreateExchangeCode)
}

// requireServiceKey validates the Authorization: Bearer <key> header.
// Fails closed in production — if the key is empty, rejects all requests.
func (h *InternalHandler) requireServiceKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.cfg.InternalServiceKey == "" {
			if h.cfg.IsDevelopment() {
				c.Next() // allow in development only
				return
			}
			slog.Error("internal: INTERNAL_SERVICE_KEY is empty in non-development environment")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "SERVICE_MISCONFIGURED"})
			return
		}

		token := middleware.ExtractBearerToken(c)
		if token != h.cfg.InternalServiceKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
			return
		}
		c.Next()
	}
}

// rateLimit enforces per-caller rate limiting on internal endpoints.
func (h *InternalHandler) rateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP() + ":" + c.Request.URL.Path
		if !h.rateLimiter.allow(key) {
			slog.Warn("internal: rate limit exceeded", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "RATE_LIMIT_EXCEEDED"})
			return
		}
		c.Next()
	}
}

// exchangeCodeData is stored in the ephemeral store, keyed by a random code.
type exchangeCodeData struct {
	UserID       string `json:"uid"`
	Email        string `json:"email"`
	TenantID     string `json:"tid"`
	TenantSlug   string `json:"ts"`
	AppName      string `json:"app"`
	IDToken      string `json:"idt"`
	RefreshToken string `json:"rt"`
	AccessToken  string `json:"at"`
	ExpiresAt    int64  `json:"exp"`
}

// CreateExchangeCode authenticates a user via GIP REST API (signInWithPassword),
// stores the resulting tokens in the ephemeral store under a one-time code, and
// returns the code. The admin app's /auth/exchange-token endpoint consumes it.
//
// Called by marketplace-onboarding after account creation to enable seamless
// cross-origin login without requiring the user to re-enter credentials.
func (h *InternalHandler) CreateExchangeCode(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required"`
		Password   string `json:"password" binding:"required"`
		TenantID   string `json:"tenant_id"`
		TenantSlug string `json:"tenant_slug" binding:"required"`
		AppName    string `json:"app_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Missing required fields"})
		return
	}

	// Validate tenant_slug format to prevent injection
	if !isValidSlug(req.TenantSlug) {
		slog.Warn("exchange-code: invalid tenant_slug format", "tenant_slug", req.TenantSlug)
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Invalid tenant slug format"})
		return
	}

	// Resolve app config to get the GIP tenant ID
	app := middleware.GetAppByName(c, req.AppName)
	if app == nil {
		slog.Warn("exchange-code: unknown app", "app_name", req.AppName)
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	if h.cfg.GIPAPIKey == "" {
		slog.Error("exchange-code: GIP_API_KEY not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SERVICE_MISCONFIGURED"})
		return
	}

	// Authenticate the user via GIP REST API to get real tokens
	result, err := h.gip.SignInWithPassword(c.Request.Context(), h.cfg.GIPAPIKey, app.GIPTenantID, req.Email, req.Password)
	if err != nil {
		slog.Warn("exchange-code: GIP signInWithPassword failed", "error", err, "email", req.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "AUTH_FAILED", "message": "Invalid credentials"})
		return
	}

	// Generate a cryptographically random one-time code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		slog.Error("exchange-code: generate random code", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "INTERNAL_ERROR"})
		return
	}
	code := hex.EncodeToString(codeBytes)

	// SECURITY: tenant_id is optional from the caller; if empty, it will be
	// resolved downstream from the tenant_slug by the admin app's middleware.
	// We log when tenant_id is provided for audit traceability.
	if req.TenantID != "" {
		slog.Info("exchange-code: tenant_id provided by caller", "tenant_id", req.TenantID, "tenant_slug", req.TenantSlug)
	}

	// Store tokens under the code (5 minute TTL, single-use via Consume)
	data := exchangeCodeData{
		UserID:       result.LocalID,
		Email:        result.Email,
		TenantID:     req.TenantID,
		TenantSlug:   req.TenantSlug,
		AppName:      req.AppName,
		IDToken:      result.IDToken,
		RefreshToken: result.RefreshToken,
		AccessToken:  result.IDToken, // GIP REST API returns idToken as access token
		ExpiresAt:    time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix(),
	}
	encoded, _ := json.Marshal(data)
	h.ephemeral.Set("xcode:"+code, encoded, 5*time.Minute)

	slog.Info("exchange-code: created",
		"user_id", result.LocalID,
		"email", result.Email,
		"tenant_id", req.TenantID,
		"tenant_slug", req.TenantSlug,
		"app", req.AppName,
		"client_ip", c.ClientIP(),
	)
	c.JSON(http.StatusOK, gin.H{"code": code})
}

// VerifyToken verifies a GIP ID token and returns user claims.
// Used by backend services to validate tokens from frontend requests.
func (h *InternalHandler) VerifyToken(c *gin.Context) {
	var req struct {
		IDToken string `json:"id_token" binding:"required"`
		AppName string `json:"app_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	// Resolve app config to get the right GIP provider
	app := middleware.GetAppByName(c, req.AppName)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	claims, err := h.gip.VerifyIDToken(c.Request.Context(), app, req.IDToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "INVALID_TOKEN"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"user_id": claims.Subject,
		"email":   claims.Email,
		"name":    claims.Name,
		"tenant":  claims.TenantID,
	})
}

// SessionExchange decrypts a session cookie and returns the access token + user claims.
// Called by tesserix-home (Next.js server) to get tokens for backend service calls.
// Replaces the old /auth/token-exchange endpoint that used Redis session lookup.
func (h *InternalHandler) SessionExchange(c *gin.Context) {
	var req struct {
		CookieName  string `json:"cookie_name" binding:"required"`
		CookieValue string `json:"cookie_value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	// Validate cookie_name against the known set of session cookie names.
	// This prevents the endpoint from being used to decrypt arbitrary cookie values.
	if !h.cfg.IsKnownSessionCookie(req.CookieName) {
		slog.Warn("session-exchange: unknown cookie name", "cookie_name", req.CookieName)
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_COOKIE_NAME"})
		return
	}

	// Strip surrounding double quotes if present — Go's http.Cookie reader
	// strips them automatically, but clients extracting from the raw Cookie
	// header may include them.
	cookieValue := strings.TrimPrefix(strings.TrimSuffix(req.CookieValue, "\""), "\"")

	sess, err := h.sessions.LoadFromValue(cookieValue)
	if err != nil {
		slog.Warn("session-exchange: decrypt failed",
			"error", err,
			"cookie_name", req.CookieName,
			"cookie_len", len(cookieValue),
			"raw_len", len(req.CookieValue),
			"starts_with_quote", strings.HasPrefix(req.CookieValue, "\""),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_SESSION"})
		return
	}

	if sess.IsExpired() {
		slog.Info("session-exchange: token expired", "user_id", sess.UserID, "expires_at", sess.ExpiresAt)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "SESSION_EXPIRED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": sess.AccessToken,
		"id_token":     sess.IDToken,
		"user_id":      sess.UserID,
		"email":        sess.Email,
		"tenant_id":    sess.TenantID,
		"tenant_slug":  sess.TenantSlug,
		"auth_context": sess.AuthContext,
		"expires_at":   sess.ExpiresAt,
	})
}
