package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/gip"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

// InternalHandler handles service-to-service requests.
// Other services call these endpoints to verify tokens or exchange session data.
type InternalHandler struct {
	cfg       *config.Config
	gip       *gip.Client
	sessions  *session.CookieStore
	ephemeral *session.EphemeralStore
}

// NewInternalHandler creates a new InternalHandler.
func NewInternalHandler(cfg *config.Config, gipClient *gip.Client, sessions *session.CookieStore, ephemeral *session.EphemeralStore) *InternalHandler {
	return &InternalHandler{cfg: cfg, gip: gipClient, sessions: sessions, ephemeral: ephemeral}
}

// RegisterRoutes registers internal endpoints.
func (h *InternalHandler) RegisterRoutes(r *gin.Engine) {
	internal := r.Group("/internal")
	internal.Use(h.requireServiceKey())

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

// exchangeCodeData is stored in the ephemeral store, keyed by a random code.
type exchangeCodeData struct {
	UserID       string `json:"uid"`
	Email        string `json:"email"`
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
		TenantSlug string `json:"tenant_slug" binding:"required"`
		AppName    string `json:"app_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Missing required fields"})
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

	// Store tokens under the code (5 minute TTL, single-use via Consume)
	data := exchangeCodeData{
		UserID:       result.LocalID,
		Email:        result.Email,
		TenantSlug:   req.TenantSlug,
		AppName:      req.AppName,
		IDToken:      result.IDToken,
		RefreshToken: result.RefreshToken,
		AccessToken:  result.IDToken, // GIP REST API returns idToken as access token
		ExpiresAt:    time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix(),
	}
	encoded, _ := json.Marshal(data)
	h.ephemeral.Set("xcode:"+code, encoded, 5*time.Minute)

	slog.Info("exchange-code: created", "user_id", result.LocalID, "app", req.AppName)
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

	sess, err := h.sessions.LoadFromValue(req.CookieValue)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_SESSION"})
		return
	}

	if sess.IsExpired() {
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
